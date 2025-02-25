// TODO: Message commands (invite to group, etc.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Structured {
    Text(String),
}

impl Structured {
    const DISC_TEXT: u32 = 1;

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Text(text) => {
                let mut buf = Vec::with_capacity(4 + text.len());

                buf.extend(u32::to_le_bytes(Self::DISC_TEXT));
                buf.extend(text.as_bytes());

                buf
            }
        }
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let discriminant = u32::from_le_bytes(bytes[0..4].try_into().ok()?);

        match discriminant {
            Self::DISC_TEXT => {
                let text = String::from_utf8(bytes[4..].to_vec()).ok()?;
                Some(Self::Text(text))
            }
            _ => None,
        }
    }
}
