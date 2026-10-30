// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Lexer for the Prometheus text format 0.0.4, a hand-written port of
//! [`promlex.l`](https://github.com/prometheus/prometheus/blob/main/model/textparse/promlex.l).

/// Lexer states, named after the start conditions in `promlex.l`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Init,
    Comment,
    /// After `# HELP` or `# TYPE`, before the metric name.
    Meta1,
    /// The rest of a `# HELP` or `# TYPE` line.
    Meta2,
    Labels,
    LValue,
    Value,
    Timestamp,
}

/// Lexer tokens, named after the tokens in Go's promparse.go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Token {
    Invalid,
    Eof,
    Linebreak,
    Whitespace,
    Help,
    Type,
    Text,
    Comment,
    MName,
    QString,
    BraceOpen,
    BraceClose,
    LName,
    LValue,
    Comma,
    Equal,
    Timestamp,
    Value,
}

fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b':'
}

fn is_label_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_name_char(byte: u8) -> bool {
    is_name_start(byte) || byte.is_ascii_digit()
}

fn is_label_char(byte: u8) -> bool {
    is_label_start(byte) || byte.is_ascii_digit()
}

/// Hand-written port of the `promlex.l` rules. The input behaves as if a `\n`
/// were appended, like Go's `append(b, '\n')`, without copying it.
pub(super) struct Lexer<'a> {
    pub(super) input: &'a [u8],
    pub(super) pos: usize,
    pub(super) token_start: usize,
    state: State,
}

impl<'a> Lexer<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            token_start: 0,
            state: State::Init,
        }
    }

    fn len(&self) -> usize {
        self.input.len() + 1
    }

    fn byte(&self, index: usize) -> u8 {
        match self.input.get(index) {
            Some(&byte) => byte,
            None if index == self.input.len() => b'\n',
            None => 0,
        }
    }

    fn current(&self) -> u8 {
        self.byte(self.pos)
    }

    pub(super) fn token(&self) -> &'a [u8] {
        let end = self.input.len();
        &self.input[self.token_start.min(end)..self.pos.min(end)]
    }

    // Go's lexer skips NUL bytes inside label values, help text and comments,
    // and returns 0 (EOF) past the end of the input.
    fn next(&mut self) -> u8 {
        self.pos += 1;
        if self.pos >= self.len() {
            return 0;
        }
        let mut byte = self.byte(self.pos);
        while byte == 0 && matches!(self.state, State::LValue | State::Meta2 | State::Comment) {
            self.pos += 1;
            byte = self.byte(self.pos);
        }
        byte
    }

    fn eat_while(&mut self, mut byte: u8, pred: impl Fn(u8) -> bool) -> u8 {
        while pred(byte) {
            byte = self.next();
        }
        byte
    }

    fn eat_after(&mut self, pred: impl Fn(u8) -> bool) -> u8 {
        let next = self.next();
        self.eat_while(next, pred)
    }

    /// Consumes `"(\\.|[^\\"])*"` starting at the opening quote.
    fn quoted(&mut self) -> bool {
        loop {
            match self.next() {
                b'"' => {
                    self.next();
                    return true;
                }
                b'\\' => {
                    if matches!(self.next(), 0 | b'\n') {
                        return false;
                    }
                }
                0 => return false,
                _ => {}
            }
        }
    }

    fn consume_comment(&mut self) -> Token {
        let mut byte = self.current();
        loop {
            match byte {
                0 => return Token::Eof,
                b'\n' => {
                    self.state = State::Init;
                    return Token::Comment;
                }
                _ => byte = self.next(),
            }
        }
    }

    fn whitespace(&mut self) -> Token {
        self.eat_after(is_blank);
        Token::Whitespace
    }

    /// Consumes one byte, then moves to `state` and returns `token`.
    fn emit(&mut self, state: State, token: Token) -> Token {
        self.next();
        self.state = state;
        token
    }

    /// Consumes a quoted string, then moves to `state` and returns `token`.
    fn emit_quoted(&mut self, state: State, token: Token) -> Token {
        if !self.quoted() {
            return Token::Invalid;
        }
        self.state = state;
        token
    }

    pub(super) fn lex(&mut self) -> Token {
        if self.pos >= self.len() {
            return Token::Eof;
        }
        self.token_start = self.pos;
        let byte = self.current();
        if is_blank(byte) && self.state != State::Meta2 {
            return self.whitespace();
        }
        match self.state {
            State::Init => self.lex_init(byte),
            State::Comment => self.lex_comment(byte),
            State::Meta1 => self.lex_meta1(byte),
            State::Meta2 => self.lex_meta2(byte),
            State::Labels => self.lex_labels(byte),
            State::LValue => self.lex_lvalue(byte),
            State::Value => self.lex_value(byte),
            State::Timestamp => self.lex_timestamp(byte),
        }
    }

    fn lex_init(&mut self, byte: u8) -> Token {
        match byte {
            0 => Token::Eof,
            b'\n' => self.emit(State::Init, Token::Linebreak),
            b'#' => {
                if !is_blank(self.next()) {
                    return self.consume_comment();
                }
                let byte = self.eat_after(is_blank);
                self.state = State::Comment;
                self.lex_comment(byte)
            }
            b'{' => self.emit(State::Labels, Token::BraceOpen),
            _ if is_name_start(byte) => {
                self.eat_after(is_name_char);
                self.state = State::Value;
                Token::MName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_comment(&mut self, byte: u8) -> Token {
        let (rest, token) = match byte {
            b'H' => (b"ELP", Token::Help),
            b'T' => (b"YPE", Token::Type),
            _ => return self.consume_comment(),
        };
        if rest.iter().all(|&expected| self.next() == expected) && is_blank(self.next()) {
            self.whitespace();
            self.state = State::Meta1;
            return token;
        }
        self.consume_comment()
    }

    fn lex_meta1(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(State::Meta2, Token::MName),
            _ if is_name_start(byte) => {
                self.eat_after(is_name_char);
                self.state = State::Meta2;
                Token::MName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_meta2(&mut self, mut byte: u8) -> Token {
        // `[ \t]+` wins over `[^\n]*` on a tie, so trailing blanks are whitespace.
        if is_blank(byte) {
            byte = self.eat_after(is_blank);
            if byte == 0 || byte == b'\n' {
                return Token::Whitespace;
            }
        }
        self.eat_while(byte, |next_byte| next_byte != 0 && next_byte != b'\n');
        self.state = State::Init;
        Token::Text
    }

    fn lex_labels(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(State::Labels, Token::QString),
            b',' => self.emit(State::Labels, Token::Comma),
            b'=' => self.emit(State::LValue, Token::Equal),
            b'}' => self.emit(State::Value, Token::BraceClose),
            _ if is_label_start(byte) => {
                self.eat_after(is_label_char);
                Token::LName
            }
            _ => Token::Invalid,
        }
    }

    fn lex_lvalue(&mut self, byte: u8) -> Token {
        match byte {
            b'"' => self.emit_quoted(State::Labels, Token::LValue),
            _ => Token::Invalid,
        }
    }

    fn lex_value(&mut self, byte: u8) -> Token {
        match byte {
            b'{' => self.emit(State::Labels, Token::BraceOpen),
            0 | b'\n' => Token::Invalid,
            _ => {
                self.eat_after(|next_byte| !matches!(next_byte, 0 | b'\n' | b' ' | b'\t' | b'{'));
                self.state = State::Timestamp;
                Token::Value
            }
        }
    }

    fn lex_timestamp(&mut self, byte: u8) -> Token {
        match byte {
            b'\n' => self.emit(State::Init, Token::Linebreak),
            b'0'..=b'9' => {
                self.eat_after(|next_byte| next_byte.is_ascii_digit());
                Token::Timestamp
            }
            _ => Token::Invalid,
        }
    }
}
