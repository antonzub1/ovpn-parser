use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alphanumeric1, digit1, line_ending, space1},
    combinator::{map_res, opt},
    multi::many0,
    sequence::{preceded, terminated},
    IResult,
};

#[derive(Default, Debug)]
struct Config {
    string_field: Option<String>,
    int_field: Option<i32>,
    bool_field: Option<bool>,
    // Add other fields as needed
}

#[derive(Debug)]
enum ConfigField {
    StringField(String),
    IntField(i32),
    BoolField(bool),
}

fn parse_string_field(input: &str) -> IResult<&str, ConfigField> {
    let (input, _) = tag("string_field")(input)?;
    let (input, _) = space1(input)?;
    let (input, value) = alphanumeric1(input)?;
    Ok((input, ConfigField::StringField(value.to_string())))
}

fn parse_int_field(input: &str) -> IResult<&str, ConfigField> {
    let (input, _) = tag("int_field")(input)?;
    let (input, _) = space1(input)?;
    let (input, value) = map_res(digit1, str::parse)(input)?;
    Ok((input, ConfigField::IntField(value)))
}

fn parse_bool_field(input: &str) -> IResult<&str, ConfigField> {
    let (input, _) = tag("bool_field")(input)?;
    let (input, _) = space1(input)?;
    let (input, value) = alt((tag("true"), tag("false")))(input)?;
    Ok((input, ConfigField::BoolField(value == "true")))
}

fn parse_field(input: &str) -> IResult<&str, ConfigField> {
    terminated(
        alt((parse_string_field, parse_int_field, parse_bool_field)),
        opt(line_ending),
    )(input)
}

fn parse_config(input: &str) -> IResult<&str, Vec<ConfigField>> {
    many0(parse_field)(input)
}

fn process_config(fields: Vec<ConfigField>) -> Config {
    let mut config = Config::default();

    for field in fields {
        match field {
            ConfigField::StringField(value) => config.string_field = Some(value),
            ConfigField::IntField(value) => config.int_field = Some(value),
            ConfigField::BoolField(value) => config.bool_field = Some(value),
        }
    }

    config
}

fn main() {
    let input = "asdfsin\nstring_field hello\nint_field 42\nbool_field true\nasdfsin";

    match parse_config(input) {
        Ok((_, fields)) => {
            let config = process_config(fields);
            println!("Parsed config: {:?}", config);
        }
        Err(e) => println!("Parsing error: {:?}", e),
    }
}
