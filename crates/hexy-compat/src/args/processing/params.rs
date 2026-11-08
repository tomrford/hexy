//! HexView 1.15.2's `/DP` and `/SV` parameter grammar:
//! `/DPn[:@placement]:[param1][,param2,param3][;param4][#NAME=value]...` and
//! `/SVn:keyinfo!signatureinfo`, where `keyinfo` takes the `/DP` parameter forms.

use std::path::PathBuf;

use crate::{AddressRange, Placement, decode_hex_text};

use super::super::parse_util::{parse_number, parse_placement_target};
use super::super::types::ParseArgError;

/// Where param1 takes its content from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::args) enum ParamSource {
    /// Hex text given inline; HexView reads any param1 that is hex text this way.
    Inline(String),
    /// `file,section,key`: the value of `key` in `[section]` of an INI file.
    Ini {
        file: PathBuf,
        section: String,
        key: String,
    },
    /// A file holding the content.
    File(PathBuf),
}

/// An `#AUTH` or `#TAG` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::args) enum DataInput {
    /// `@address,length`: bytes of the image.
    Image(AddressRange),
    /// Inline hex text.
    Hex(Vec<u8>),
    /// A file, read or written by the method.
    File(PathBuf),
}

/// The `#` options. Names are case-sensitive; HexView ignores unknown ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::args) struct ProcessingOptions {
    /// `#SALT=hex`
    pub salt: Option<Vec<u8>>,
    /// `#IV=hex`
    pub iv: Option<Vec<u8>>,
    /// `#AUTH=@address,length`, hex text or a file.
    pub auth: Option<DataInput>,
    /// `#TAG=@address,length`, hex text or a file.
    pub tag: Option<DataInput>,
    /// `#LZSS=window,length` or `#LZSSwindow,length`, in bits.
    pub lzss: Option<(u8, u8)>,
}

impl ProcessingOptions {
    /// Names of the options that are set.
    pub(in crate::args) fn names(&self) -> impl Iterator<Item = &'static str> {
        [
            ("#SALT", self.salt.is_some()),
            ("#IV", self.iv.is_some()),
            ("#AUTH", self.auth.is_some()),
            ("#TAG", self.tag.is_some()),
            ("#LZSS", self.lzss.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, set)| set.then_some(name))
    }
}

#[derive(Debug, Clone)]
pub(in crate::args) struct DataProcessingParams {
    pub method: u8,
    pub placement: Option<Placement>,
    pub source: ParamSource,
    /// param4: the output file of methods that produce output.
    pub param4: Option<String>,
    pub options: ProcessingOptions,
}

#[derive(Debug, Clone)]
pub(in crate::args) struct SignatureVerifyParams {
    pub method: u8,
    pub key: ParamSource,
    /// `None` when `!signatureinfo` is missing.
    pub signature: Option<String>,
}

pub(in crate::args) fn parse_data_processing(
    method: u8,
    value: &str,
) -> Result<DataProcessingParams, ParseArgError> {
    let (placement, rest) = match value.strip_prefix('@') {
        Some(rest) => {
            let (target, rest) = rest.split_once(':').ok_or_else(|| {
                ParseArgError::InvalidOption(format!("/DP{method} placement missing ':'"))
            })?;
            (Some(parse_placement_target(target)?), rest)
        }
        None => (None, value),
    };
    let (main, options) = rest.split_once('#').unwrap_or((rest, ""));
    let (params, param4) = main.split_once(';').unwrap_or((main, ""));
    if param4.contains(';') {
        return Err(ParseArgError::InvalidOption(format!(
            "/DP{method} has more than one ';'"
        )));
    }
    Ok(DataProcessingParams {
        method,
        placement,
        source: parse_source(params),
        param4: (!param4.is_empty()).then(|| param4.to_owned()),
        options: parse_options(options)?,
    })
}

pub(in crate::args) fn parse_signature_verify(method: u8, value: &str) -> SignatureVerifyParams {
    let mut parts = value.split('!');
    let key_info = parts.next().unwrap_or_default();
    let key_params = key_info.split(['#', ';']).next().unwrap_or_default();
    SignatureVerifyParams {
        method,
        key: parse_source(key_params),
        signature: parts.next().map(str::to_owned),
    }
}

fn parse_source(params: &str) -> ParamSource {
    if let [file, section, key] = params.split(',').collect::<Vec<_>>()[..] {
        return ParamSource::Ini {
            file: PathBuf::from(file),
            section: section.to_owned(),
            key: key.to_owned(),
        };
    }
    if decode_hex_text(params.as_bytes()).is_some() {
        ParamSource::Inline(params.to_owned())
    } else {
        ParamSource::File(PathBuf::from(params))
    }
}

fn parse_options(text: &str) -> Result<ProcessingOptions, ParseArgError> {
    let mut options = ProcessingOptions::default();
    if text.is_empty() {
        return Ok(options);
    }
    for token in text.split('#') {
        if let Some(value) = token.strip_prefix("SALT=") {
            options.salt = Some(parse_hex(token, value)?);
        } else if let Some(value) = token.strip_prefix("IV=") {
            options.iv = Some(parse_hex(token, value)?);
        } else if let Some(value) = token.strip_prefix("AUTH=") {
            options.auth = Some(parse_data_input(value)?);
        } else if let Some(value) = token.strip_prefix("TAG=") {
            options.tag = Some(parse_data_input(value)?);
        } else if let Some(value) = token.strip_prefix("LZSS") {
            options.lzss = Some(parse_lzss(token, value.strip_prefix('=').unwrap_or(value))?);
        }
    }
    Ok(options)
}

fn invalid_option(token: &str) -> ParseArgError {
    ParseArgError::InvalidOption(format!("#{token}"))
}

fn parse_hex(token: &str, value: &str) -> Result<Vec<u8>, ParseArgError> {
    decode_hex_text(value.as_bytes()).ok_or_else(|| invalid_option(token))
}

fn parse_data_input(value: &str) -> Result<DataInput, ParseArgError> {
    if let Some(range) = value.strip_prefix('@') {
        let (start, length) = range
            .split_once(',')
            .ok_or_else(|| ParseArgError::InvalidRange(range.to_owned()))?;
        let range =
            AddressRange::from_start_length(parse_number(start)?, u64::from(parse_number(length)?))
                .map_err(|e| ParseArgError::InvalidRange(e.to_string()))?;
        return Ok(DataInput::Image(range));
    }
    Ok(match decode_hex_text(value.as_bytes()) {
        Some(bytes) => DataInput::Hex(bytes),
        None => DataInput::File(PathBuf::from(value)),
    })
}

fn parse_lzss(token: &str, value: &str) -> Result<(u8, u8), ParseArgError> {
    let (window, length) = value.split_once(',').ok_or_else(|| invalid_option(token))?;
    let bits = |text: &str| text.parse::<u8>().map_err(|_| invalid_option(token));
    Ok((bits(window)?, bits(length)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Forms probed against HexView 1.15.2: everything after the first `#` is options
    /// (so `#FOO;sig.txt` has no param4), and param1 is hex text, a file or an INI
    /// reference.
    #[test]
    fn test_parse_data_processing_grammar() {
        let params = parse_data_processing(32, "@0x3000:k.ini,Keys,Private;sig.txt#IV=00").unwrap();
        assert_eq!(params.placement, Some(Placement::Address(0x3000)));
        assert_eq!(
            params.source,
            ParamSource::Ini {
                file: PathBuf::from("k.ini"),
                section: "Keys".to_owned(),
                key: "Private".to_owned()
            }
        );
        assert_eq!(params.param4.as_deref(), Some("sig.txt"));
        assert_eq!(params.options.iv, Some(vec![0]));

        let params = parse_data_processing(32, "rsa.pem#FOO;sig.txt").unwrap();
        assert_eq!(params.source, ParamSource::File(PathBuf::from("rsa.pem")));
        assert_eq!(params.param4, None);
        assert!(parse_data_processing(32, "rsa.pem#IV=00;sig.txt").is_err());

        let inline = |value: &str| parse_data_processing(1, value).unwrap().source;
        assert_eq!(
            inline("0x1234abc"),
            ParamSource::Inline("0x1234abc".to_owned())
        );
        assert_eq!(
            inline("1234,abc"),
            ParamSource::Inline("1234,abc".to_owned())
        );
        assert_eq!(inline("0X1234"), ParamSource::File(PathBuf::from("0X1234")));
        assert_eq!(inline(""), ParamSource::Inline(String::new()));
    }

    #[test]
    fn test_parse_processing_options() {
        let options = parse_data_processing(
            55,
            "00#AUTH=@0x1000,32#TAG=tag.dat#SALT=11#LZSS12,5#iv=00#FOO=1",
        )
        .unwrap()
        .options;
        assert_eq!(
            options,
            ProcessingOptions {
                salt: Some(vec![0x11]),
                iv: None,
                auth: Some(DataInput::Image(
                    AddressRange::from_start_length(0x1000, 32).unwrap()
                )),
                tag: Some(DataInput::File(PathBuf::from("tag.dat"))),
                lzss: Some((12, 5)),
            }
        );
        let options = parse_data_processing(59, "00#LZSS=12,4#TAG=0011")
            .unwrap()
            .options;
        assert_eq!(options.lzss, Some((12, 4)));
        assert_eq!(options.tag, Some(DataInput::Hex(vec![0x00, 0x11])));
    }

    /// `/SV` key info drops `;param4` and `#` options; text after a second `!` is ignored.
    #[test]
    fn test_parse_signature_verify_grammar() {
        let params = parse_signature_verify(4, "pub.txt;x!0011!zz");
        assert_eq!(params.key, ParamSource::File(PathBuf::from("pub.txt")));
        assert_eq!(params.signature.as_deref(), Some("0011"));
        assert_eq!(parse_signature_verify(4, "pub.txt").signature, None);
    }
}
