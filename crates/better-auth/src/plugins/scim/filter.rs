use super::resources::{normalize_scim_attribute, scim_attribute};
use better_auth_core::error::{AuthError, Result};

#[derive(Clone, Debug)]
pub(super) enum ScimFilter {
    All,
    Present(String),
    Compare {
        attribute: String,
        operator: ScimCompare,
        expected: String,
    },
    ValuePath {
        base: String,
        subfilter: Box<Self>,
        attribute: String,
        operator: ScimCompare,
        expected: String,
    },
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ScimCompare {
    Eq,
    Ne,
    Contains,
    StartsWith,
    EndsWith,
    GreaterThan,
    GreaterOrEqual,
    LessThan,
    LessOrEqual,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ScimFilterToken {
    Word(String),
    Value(String),
    Open,
    Close,
    OpenBracket,
    CloseBracket,
    Dot,
}

impl ScimFilter {
    pub(super) fn parse(filter: Option<&str>) -> Result<Self> {
        let Some(filter) = filter.map(str::trim).filter(|filter| !filter.is_empty()) else {
            return Ok(Self::All);
        };
        let mut parser = ScimFilterParser {
            tokens: tokenize_scim_filter(filter)?,
            position: 0,
        };
        let result = parser.parse_or()?;
        if parser.position != parser.tokens.len() {
            return Err(AuthError::InvalidRequest(
                "unexpected tokens at end of SCIM filter".into(),
            ));
        }
        Ok(result)
    }

    pub(super) fn matches(&self, user: &serde_json::Value) -> bool {
        match self {
            Self::All => true,
            Self::Present(attribute) => scim_attribute(user, attribute).is_some(),
            Self::Compare {
                attribute,
                operator,
                expected,
            } => scim_compare_matches(user, attribute, *operator, expected),
            Self::ValuePath {
                base,
                subfilter,
                attribute,
                operator,
                expected,
            } => {
                if base != "emails" || attribute != "email" {
                    return false;
                }
                let Some(email) = user.get("email").and_then(serde_json::Value::as_str) else {
                    return false;
                };
                let synthetic = serde_json::json!({
                    "type": "work",
                    "email": email,
                });
                subfilter.matches(&synthetic) && scim_compare_value(email, *operator, expected)
            }
            Self::And(left, right) => left.matches(user) && right.matches(user),
            Self::Or(left, right) => left.matches(user) || right.matches(user),
        }
    }
}

fn scim_compare_matches(
    user: &serde_json::Value,
    attribute: &str,
    operator: ScimCompare,
    expected: &str,
) -> bool {
    let Some(actual) = scim_attribute(user, attribute) else {
        return false;
    };
    scim_compare_value(&actual, operator, expected)
}

fn scim_compare_value(actual: &str, operator: ScimCompare, expected: &str) -> bool {
    match operator {
        ScimCompare::Eq => actual.eq_ignore_ascii_case(expected),
        ScimCompare::Ne => !actual.eq_ignore_ascii_case(expected),
        ScimCompare::Contains => actual
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase()),
        ScimCompare::StartsWith => actual
            .to_ascii_lowercase()
            .starts_with(&expected.to_ascii_lowercase()),
        ScimCompare::EndsWith => actual
            .to_ascii_lowercase()
            .ends_with(&expected.to_ascii_lowercase()),
        ScimCompare::GreaterThan => compare_scim_values(actual, expected).is_gt(),
        ScimCompare::GreaterOrEqual => compare_scim_values(actual, expected).is_ge(),
        ScimCompare::LessThan => compare_scim_values(actual, expected).is_lt(),
        ScimCompare::LessOrEqual => compare_scim_values(actual, expected).is_le(),
    }
}

struct ScimFilterParser {
    tokens: Vec<ScimFilterToken>,
    position: usize,
}

impl ScimFilterParser {
    fn parse_or(&mut self) -> Result<ScimFilter> {
        let mut result = self.parse_and()?;
        while self.take_word("or") {
            result = ScimFilter::Or(Box::new(result), Box::new(self.parse_and()?));
        }
        Ok(result)
    }

    fn parse_and(&mut self) -> Result<ScimFilter> {
        let mut result = self.parse_factor()?;
        while self.take_word("and") {
            result = ScimFilter::And(Box::new(result), Box::new(self.parse_factor()?));
        }
        Ok(result)
    }

    fn parse_factor(&mut self) -> Result<ScimFilter> {
        if self.take_token(ScimFilterToken::Open) {
            let result = self.parse_or()?;
            if !self.take_token(ScimFilterToken::Close) {
                return Err(AuthError::InvalidRequest(
                    "unclosed parenthesis in SCIM filter".into(),
                ));
            }
            return Ok(result);
        }
        let raw_attribute = match self.next() {
            Some(ScimFilterToken::Word(attribute)) => attribute,
            _ => {
                return Err(AuthError::InvalidRequest(
                    "SCIM filter must start with an attribute".into(),
                ))
            }
        };
        let attribute = normalize_scim_attribute(&raw_attribute)?;
        if self.take_token(ScimFilterToken::OpenBracket) {
            let subfilter = self.parse_or()?;
            if !self.take_token(ScimFilterToken::CloseBracket)
                || !self.take_token(ScimFilterToken::Dot)
            {
                return Err(AuthError::InvalidRequest(
                    "invalid SCIM valuePath filter".into(),
                ));
            }
            let value_attribute = match self.next() {
                Some(ScimFilterToken::Word(value)) => normalize_scim_attribute(&value)?,
                _ => {
                    return Err(AuthError::InvalidRequest(
                        "SCIM valuePath is missing an attribute".into(),
                    ))
                }
            };
            let operator = match self.next() {
                Some(ScimFilterToken::Word(operator)) => scim_compare_operator(&operator)?,
                _ => {
                    return Err(AuthError::InvalidRequest(
                        "SCIM valuePath is missing an operator".into(),
                    ))
                }
            };
            let expected = match self.next() {
                Some(ScimFilterToken::Word(value) | ScimFilterToken::Value(value)) => value,
                _ => {
                    return Err(AuthError::InvalidRequest(
                        "SCIM valuePath is missing a value".into(),
                    ))
                }
            };
            return Ok(ScimFilter::ValuePath {
                base: attribute,
                subfilter: Box::new(subfilter),
                attribute: value_attribute,
                operator,
                expected,
            });
        }
        let operator = match self.next() {
            Some(ScimFilterToken::Word(operator)) => operator.to_ascii_lowercase(),
            _ => {
                return Err(AuthError::InvalidRequest(
                    "SCIM filter is missing an operator".into(),
                ))
            }
        };
        if operator == "pr" {
            return Ok(ScimFilter::Present(attribute));
        }
        let operator = scim_compare_operator(&operator)?;
        let expected = match self.next() {
            Some(ScimFilterToken::Word(value) | ScimFilterToken::Value(value)) => value,
            _ => {
                return Err(AuthError::InvalidRequest(
                    "SCIM comparison is missing a value".into(),
                ))
            }
        };
        Ok(ScimFilter::Compare {
            attribute,
            operator,
            expected,
        })
    }

    fn next(&mut self) -> Option<ScimFilterToken> {
        let token = self.tokens.get(self.position).cloned();
        if token.is_some() {
            self.position += 1;
        }
        token
    }

    fn take_token(&mut self, expected: ScimFilterToken) -> bool {
        if self.tokens.get(self.position) == Some(&expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn take_word(&mut self, expected: &str) -> bool {
        if matches!(
            self.tokens.get(self.position),
            Some(ScimFilterToken::Word(word)) if word.eq_ignore_ascii_case(expected)
        ) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

fn scim_compare_operator(operator: &str) -> Result<ScimCompare> {
    match operator.to_ascii_lowercase().as_str() {
        "eq" => Ok(ScimCompare::Eq),
        "ne" => Ok(ScimCompare::Ne),
        "co" => Ok(ScimCompare::Contains),
        "sw" => Ok(ScimCompare::StartsWith),
        "ew" => Ok(ScimCompare::EndsWith),
        "gt" => Ok(ScimCompare::GreaterThan),
        "ge" => Ok(ScimCompare::GreaterOrEqual),
        "lt" => Ok(ScimCompare::LessThan),
        "le" => Ok(ScimCompare::LessOrEqual),
        _ => Err(AuthError::InvalidRequest(
            "unsupported SCIM filter operator".into(),
        )),
    }
}

fn tokenize_scim_filter(filter: &str) -> Result<Vec<ScimFilterToken>> {
    let characters = filter.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut position = 0;
    while position < characters.len() {
        if characters[position].is_whitespace() {
            position += 1;
        } else if characters[position] == '(' {
            tokens.push(ScimFilterToken::Open);
            position += 1;
        } else if characters[position] == ')' {
            tokens.push(ScimFilterToken::Close);
            position += 1;
        } else if characters[position] == '[' {
            tokens.push(ScimFilterToken::OpenBracket);
            position += 1;
        } else if characters[position] == ']' {
            tokens.push(ScimFilterToken::CloseBracket);
            position += 1;
        } else if characters[position] == '.' {
            tokens.push(ScimFilterToken::Dot);
            position += 1;
        } else if matches!(characters[position], '"' | '\'') {
            let quote = characters[position];
            position += 1;
            let mut value = String::new();
            let mut closed = false;
            while position < characters.len() {
                let character = characters[position];
                position += 1;
                if character == quote {
                    closed = true;
                    break;
                }
                if character == '\\' && position < characters.len() {
                    value.push(characters[position]);
                    position += 1;
                } else {
                    value.push(character);
                }
            }
            if !closed {
                return Err(AuthError::InvalidRequest(
                    "unterminated quoted value in SCIM filter".into(),
                ));
            }
            tokens.push(ScimFilterToken::Value(value));
        } else {
            let start = position;
            while position < characters.len()
                && !characters[position].is_whitespace()
                && !matches!(characters[position], '(' | ')' | '[' | ']' | '.')
            {
                position += 1;
            }
            tokens.push(ScimFilterToken::Word(
                characters[start..position].iter().collect(),
            ));
        }
    }
    Ok(tokens)
}

fn compare_scim_values(actual: &str, expected: &str) -> std::cmp::Ordering {
    match (actual.parse::<f64>(), expected.parse::<f64>()) {
        (Ok(actual), Ok(expected)) => actual
            .partial_cmp(&expected)
            .unwrap_or(std::cmp::Ordering::Equal),
        _ => actual
            .to_ascii_lowercase()
            .cmp(&expected.to_ascii_lowercase()),
    }
}
