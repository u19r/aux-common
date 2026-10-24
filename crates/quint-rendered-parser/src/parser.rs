use std::collections::BTreeMap;

/// The structural subset of Quint syntax emitted in connector step output.
#[derive(Debug, Eq, PartialEq)]
pub enum RenderedValue {
    Bool(bool),
    Integer(i64),
    Text(String),
    Atom(String),
    Tuple(Vec<Self>),
    Record(BTreeMap<String, Self>),
    Variant(String, Box<Self>),
}

/// Parse one complete Quint-rendered value.
pub fn parse(input: &str) -> std::io::Result<RenderedValue> {
    Parser::new(input).parse()
}

struct Parser {
    input: Vec<char>,
    position: usize,
}

impl Parser {
    fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            position: 0,
        }
    }

    fn parse(mut self) -> std::io::Result<RenderedValue> {
        let value = self.value()?;
        self.whitespace();
        if self.position == self.input.len() {
            Ok(value)
        } else {
            Err(std::io::Error::other(format!(
                "trailing rendered value syntax at character {}",
                self.position
            )))
        }
    }

    fn value(&mut self) -> std::io::Result<RenderedValue> {
        self.whitespace();
        match self.peek() {
            Some('{') => self.record(),
            Some('(') => self.tuple(),
            Some('"') => self.text(),
            Some('-' | '0'..='9') => self.number(),
            Some(_) => self.atom_or_variant(),
            None => Err(std::io::Error::other("missing rendered value")),
        }
    }

    fn record(&mut self) -> std::io::Result<RenderedValue> {
        self.expect('{')?;
        let mut fields = BTreeMap::new();
        loop {
            self.whitespace();
            if self.take('}') {
                return Ok(RenderedValue::Record(fields));
            }
            let key = self.identifier()?;
            self.whitespace();
            self.expect(':')?;
            let value = self.value()?;
            if fields.insert(key.clone(), value).is_some() {
                return Err(std::io::Error::other(format!(
                    "duplicate rendered value field {key}"
                )));
            }
            self.whitespace();
            if self.take('}') {
                return Ok(RenderedValue::Record(fields));
            }
            self.expect(',')?;
            self.whitespace();
            if self.peek() == Some('}') {
                return Err(std::io::Error::other(
                    "trailing rendered value record separator",
                ));
            }
        }
    }

    fn tuple(&mut self) -> std::io::Result<RenderedValue> {
        self.expect('(')?;
        let mut values = Vec::new();
        loop {
            self.whitespace();
            if self.take(')') {
                return Ok(RenderedValue::Tuple(values));
            }
            values.push(self.value()?);
            self.whitespace();
            if self.take(')') {
                return Ok(RenderedValue::Tuple(values));
            }
            self.expect(',')?;
            self.whitespace();
            if self.peek() == Some(')') {
                return Err(std::io::Error::other(
                    "trailing rendered value tuple separator",
                ));
            }
        }
    }

    fn text(&mut self) -> std::io::Result<RenderedValue> {
        self.expect('"')?;
        let mut value = String::new();
        loop {
            let Some(character) = self.next() else {
                return Err(std::io::Error::other("unterminated rendered value string"));
            };
            match character {
                '"' => return Ok(RenderedValue::Text(value)),
                '\\' => {
                    let Some(escaped) = self.next() else {
                        return Err(std::io::Error::other(
                            "unterminated rendered value string escape",
                        ));
                    };
                    value.push(escaped);
                }
                character => value.push(character),
            }
        }
    }

    fn number(&mut self) -> std::io::Result<RenderedValue> {
        let start = self.position;
        if self.take('-') && !self.peek().is_some_and(|value| value.is_ascii_digit()) {
            return Err(std::io::Error::other("invalid rendered value number"));
        }
        while self.peek().is_some_and(|value| value.is_ascii_digit()) {
            self.position = self.position.saturating_add(1);
        }
        let value: String = self.input[start..self.position].iter().collect();
        let integer = value.parse::<i64>().map_err(|error| {
            std::io::Error::other(format!("invalid rendered value integer {value}: {error}"))
        })?;
        Ok(RenderedValue::Integer(integer))
    }

    fn atom_or_variant(&mut self) -> std::io::Result<RenderedValue> {
        let name = self.identifier()?;
        if name == "true" {
            return Ok(RenderedValue::Bool(true));
        }
        if name == "false" {
            return Ok(RenderedValue::Bool(false));
        }
        self.whitespace();
        if !self.take('(') {
            return Ok(RenderedValue::Atom(name));
        }
        let mut values = Vec::new();
        self.whitespace();
        if !self.take(')') {
            values.push(self.value()?);
            self.whitespace();
            while self.take(',') {
                values.push(self.value()?);
                self.whitespace();
            }
            self.expect(')')?;
        }
        let payload = match values.len() {
            0 => RenderedValue::Tuple(values),
            1 => values
                .pop()
                .ok_or_else(|| std::io::Error::other("variant payload disappeared"))?,
            _ => RenderedValue::Tuple(values),
        };
        Ok(RenderedValue::Variant(name, Box::new(payload)))
    }

    fn identifier(&mut self) -> std::io::Result<String> {
        let start = self.position;
        while self
            .peek()
            .is_some_and(|value| value.is_ascii_alphanumeric() || matches!(value, '_' | '-'))
        {
            self.position = self.position.saturating_add(1);
        }
        if self.position == start {
            return Err(std::io::Error::other(format!(
                "expected rendered value identifier at character {}",
                self.position
            )));
        }
        Ok(self.input[start..self.position].iter().collect())
    }

    fn whitespace(&mut self) {
        while self.peek().is_some_and(|value| value.is_ascii_whitespace()) {
            self.position = self.position.saturating_add(1);
        }
    }

    fn expect(&mut self, expected: char) -> std::io::Result<()> {
        if self.take(expected) {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "expected {expected:?} in rendered value at character {}",
                self.position
            )))
        }
    }

    fn take(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.position = self.position.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Option<char> {
        let value = self.peek()?;
        self.position = self.position.saturating_add(1);
        Some(value)
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.position).copied()
    }
}
