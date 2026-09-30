"""
ARGUS - Math and unit conversion.

Handled locally with a restricted parser rather than sent to the model. A
language model doing arithmetic is both slower and less reliable than actually
computing it.

Security note: eval() on user input is normally a serious vulnerability. Here
the expression is whitelist-validated character by character, then PARSED and
checked as a syntax tree, and only then evaluated with empty builtins -- so
only digits, operators, and a fixed set of math functions can reach it: no
attribute access, no imports, no names, no comprehensions, no lambdas.

The tree check is not belt-and-braces. A character whitelist cannot see
structure, and structure is where the danger was: the exponent guard it
replaced was a regex over adjacent number pairs, and "10**10**10" walked past
it and pinned a CPU core for as long as it was left running. See _check_ast.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ast
import math
import re

ALLOWED_NAMES = {
    "abs": abs, "round": round, "min": min, "max": max, "pow": pow,
    "sqrt": math.sqrt, "floor": math.floor, "ceil": math.ceil,
    "sin": math.sin, "cos": math.cos, "tan": math.tan, "log": math.log,
    "log10": math.log10, "exp": math.exp, "pi": math.pi, "e": math.e,
}

SAFE_PATTERN = re.compile(r"^[0-9\s\+\-\*/\.\(\)%,a-z_]+$")

WORD_OPS = [
    (r"\bplus\b|\band\b", "+"),
    (r"\bminus\b|\bless\b", "-"),
    (r"\btimes\b|\bmultiplied by\b|\bx\b", "*"),
    (r"\bdivided by\b|\bover\b", "/"),
    (r"\bsquared\b", "**2"),
    (r"\bcubed\b", "**3"),
    (r"\bpercent of\b", "/100*"),
    (r"\bsquare root of\b", "sqrt"),
    (r"\bto the power of\b", "**"),
]

# (aliases) -> (canonical, factor to base unit)
UNITS = {
    "length": {
        "base": "metre",
        "u": {
            "mm": .001, "millimetre": .001, "millimeter": .001,
            "cm": .01, "centimetre": .01, "centimeter": .01,
            "m": 1, "metre": 1, "meter": 1,
            "km": 1000, "kilometre": 1000, "kilometer": 1000,
            "in": .0254, "inch": .0254, "inches": .0254,
            "ft": .3048, "foot": .3048, "feet": .3048,
            "yd": .9144, "yard": .9144,
            "mi": 1609.34, "mile": 1609.34, "miles": 1609.34,
        },
    },
    "mass": {
        "base": "kilogram",
        "u": {
            "g": .001, "gram": .001, "grams": .001,
            "kg": 1, "kilo": 1, "kilogram": 1, "kilograms": 1,
            "lb": .453592, "pound": .453592, "pounds": .453592,
            "oz": .0283495, "ounce": .0283495, "ounces": .0283495,
            "tonne": 1000, "ton": 907.185,
        },
    },
    # "how many minutes in an hour" / "convert 90 minutes to hours" is one of
    # the commonest conversions anyone asks aloud, and the skill answered "I
    # don't know one of those units" because there was no time family at all.
    # Note "m" is deliberately absent -- it already means metre in the length
    # family, and a silent unit collision is worse than not answering.
    "time": {
        "base": "second",
        "u": {
            "sec": 1, "secs": 1, "second": 1,
            "min": 60, "mins": 60, "minute": 60,
            "hr": 3600, "hrs": 3600, "hour": 3600,
            "day": 86400, "week": 604800,
        },
    },
    "volume": {
        "base": "litre",
        "u": {
            "ml": .001, "millilitre": .001, "milliliter": .001,
            "l": 1, "litre": 1, "liter": 1, "litres": 1, "liters": 1,
            "cup": .236588, "cups": .236588,
            "pint": .473176, "pints": .473176,
            "gallon": 3.78541, "gallons": 3.78541,
        },
    },
}


def _clean_expression(text: str) -> str:
    t = text.lower()
    t = re.sub(r"^(what(?:'s| is)|calculate|compute|work out|how much is)\s+", "", t)
    t = t.replace("?", "").strip()
    t = re.sub(r"^the\s+", "", t)

    # Symbolic and abbreviated forms, handled BEFORE the word-operator pass.
    #
    # WORD_OPS only knows the fully spelled-out phrasings, so "15 percent of
    # 240" worked while "15% of 240" was refused as unparseable -- and the
    # second is how people actually write it. Same for "sqrt of 169" against
    # "square root of 169". A calculator that answers one phrasing and rejects
    # its obvious synonym reads as broken, not as strict.

    # "10% off 50" is a DISCOUNT, not a percentage-of: the answer is 45, not 5.
    # Handled first, because the "%" rule below would otherwise consume it and
    # silently return the wrong number -- which is worse than refusing.
    t = re.sub(r"([\d.]+)\s*(?:%|percent)\s+off\s+([\d.]+)",
               r"\2*(1-\1/100)", t)
    # "15% of 240" -> "15/100*240"
    t = re.sub(r"([\d.]+)\s*%\s+of\b", r"\1/100*", t)
    # A trailing bare "%" with no "of": "20% of" is handled above, so this is
    # "what is 20%" -> 0.2
    t = re.sub(r"([\d.]+)\s*%(?!\s*of)", r"(\1/100)", t)

    # "square root of 144" / "sqrt of 144" / "sqrt 144" -> "sqrt(144)". Needs
    # handling before the generic word-operator pass, since it takes an
    # argument rather than being infix.
    t = re.sub(r"(?:square root|sqrt|root)(?:\s+of)?\s+([\d.]+)", r"sqrt(\1)", t)

    for pat, rep in WORD_OPS:
        t = re.sub(pat, rep, t)
    t = re.sub(r"[^0-9\s\+\-\*/\.\(\)%a-z_]", "", t)
    return t.strip()


# The only node types an arithmetic expression needs. Anything else -- an
# attribute access, a subscript, a comprehension, a lambda -- is rejected
# outright rather than relying on {"__builtins__": {}} to contain it.
_ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.Name, ast.Call,
    ast.Load, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
    ast.Pow, ast.USub, ast.UAdd,
)

# Beyond this, formatting and speaking the number are pointless anyway.
_MAX_POW_RESULT_DIGITS = 300


def _static_value(node):
    """The numeric value of NODE if it can be known without running anything,
    else None. Only needs to handle literals and negated literals -- that is
    all a bound check requires."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        inner = _static_value(node.operand)
        if inner is None:
            return None
        return -inner if isinstance(node.op, ast.USub) else inner
    return None


def _check_ast(node):
    """(ok, message). Walks the parsed expression and refuses anything that is
    not plain arithmetic, or any power whose size cannot be proven small."""
    for sub in ast.walk(node):
        if not isinstance(sub, _ALLOWED_NODES):
            return False, "I couldn't parse that as a calculation."
        if isinstance(sub, ast.Call):
            # Only a bare whitelisted name may be called -- never an attribute,
            # and never something computed.
            if not isinstance(sub.func, ast.Name) or sub.func.id not in ALLOWED_NAMES:
                return False, "I couldn't parse that as a calculation."
            if sub.keywords:
                return False, "I couldn't parse that as a calculation."
        if isinstance(sub, ast.Name) and sub.id not in ALLOWED_NAMES:
            return False, "I couldn't parse that as a calculation."
        if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Pow):
            base = _static_value(sub.left)
            exp = _static_value(sub.right)
            # A power whose operands are not both literal numbers cannot be
            # bounded here -- 10**10**10 has a Pow as its own exponent, and
            # (9**9)**9**9 has one as its base. Refuse rather than guess.
            if base is None or exp is None:
                return False, "That number is too large for me to work out."
            try:
                if abs(exp) > 1000 or abs(base) ** min(abs(exp), 100) > 1e300:
                    return False, "That number is too large for me to work out."
                # Digit count of the real result, which is what actually costs.
                if base and abs(exp) * math.log10(max(abs(base), 1.0000001)) > _MAX_POW_RESULT_DIGITS:
                    return False, "That number is too large for me to work out."
            except (ValueError, OverflowError):
                return False, "That number is too large for me to work out."
    return True, ""


def calculate(text: str) -> str:
    expr = _clean_expression(text)
    if not expr or not SAFE_PATTERN.match(expr):
        return "I couldn't parse that as a calculation."

    # Reject any identifier that isn't in our whitelist.
    for name in re.findall(r"[a-z_]+", expr):
        if name not in ALLOWED_NAMES:
            return "I couldn't parse that as a calculation."

    # Reject absurd exponents before evaluating. "9 to the power of 999999"
    # computes a multi-megabyte integer and hangs the orchestrator -- a denial
    # of service triggerable by a single spoken sentence.
    #
    # BUGFIX: this guard used to be a regex, re.findall(r"([\d.]+)\*\*([\d.]+)"),
    # which only ever inspected ADJACENT NUMBER PAIRS and so never saw the
    # shape of the expression it was defending. Two spoken sentences walked
    # straight past it and pinned a CPU core indefinitely:
    #
    #     10**10**10      the regex sees only "10**10" (harmless); Python
    #                     evaluates ** right-associative, so this is
    #                     10 to the power of ten billion
    #     (9**9)**9**9    the regex sees two innocent "9**9" pairs; the real
    #                     value is 387420489 ** 387420489
    #
    # Measured: a single such call burned 310 seconds of CPU and was still
    # running when killed. On the live system that is an orchestrator
    # threadpool thread, so ARGUS simply stops answering.
    #
    # A regex cannot fix this, because the danger is in the tree, not the
    # text. The expression is parsed and bounded structurally below instead.
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return "I couldn't parse that as a calculation."

    ok, why = _check_ast(tree.body)
    if not ok:
        return why

    try:
        result = eval(compile(tree, "<calc>", "eval"),
                      {"__builtins__": {}}, ALLOWED_NAMES)
    except Exception:
        return "That doesn't work out to a number."

    # Guard the result too  log/exp can produce values that break formatting.
    try:
        if isinstance(result, int) and abs(result) > 10 ** 100:
            return "That result is too large to say out loud."
    except (TypeError, OverflowError):
        return "That doesn't work out to a number."

    if isinstance(result, float):
        if result.is_integer():
            result = int(result)
        else:
            result = round(result, 6)
    return f"That's {result}."


def _find_unit(token: str):
    """Resolves a spoken unit word, singular or plural.

    BUGFIX: plurals used to be hand-added one at a time, so the table had
    "miles", "pounds", "grams" and "inches" but NOT "kilometers", "kilometres",
    "millilitres", "milliliters", "meters", "yards" or "tonnes". "convert 5
    miles to kilometers" -- about as ordinary a request as this skill gets --
    answered "I don't know one of those units", because the SECOND unit was
    plural and nobody had typed that one in.

    Stripping the plural suffix handles every case uniformly instead of
    depending on someone remembering to add each new one. The hand-added
    plurals still in UNITS are now redundant but harmless.
    """
    token = token.lower().rstrip(".")
    candidates = [token]
    if token.endswith("es") and len(token) > 3:
        candidates.append(token[:-2])
    if token.endswith("s") and len(token) > 2:
        candidates.append(token[:-1])
    for candidate in candidates:
        for family, data in UNITS.items():
            if candidate in data["u"]:
                return family, candidate, data["u"][candidate]
    return None


def convert(text: str) -> str:
    t = text.lower().replace("?", "")

    # temperature is affine, not a simple factor  handle separately
    m = re.search(r"(-?[\d.]+)\s*(?:degrees?\s*)?(c|celsius|f|fahrenheit)\b.*?\b(c|celsius|f|fahrenheit)\b", t)
    if m:
        val = float(m.group(1))
        src, dst = m.group(2)[0], m.group(3)[0]
        if src == dst:
            return f"That's still {val:g} degrees."
        if src == "c":
            return f"That's {val * 9 / 5 + 32:.1f} degrees Fahrenheit."
        return f"That's {(val - 32) * 5 / 9:.1f} degrees Celsius."

    m = re.search(r"(-?[\d.]+)\s*([a-z]+)\s*(?:in|to|into)\s*([a-z]+)", t)
    if not m:
        return "I couldn't work out what you're converting."

    val = float(m.group(1))
    a, b = _find_unit(m.group(2)), _find_unit(m.group(3))
    if not a or not b:
        return "I don't know one of those units."
    if a[0] != b[0]:
        return f"I can't convert {a[0]} into {b[0]}."

    result = val * a[2] / b[2]
    result = int(result) if float(result).is_integer() else round(result, 4)
    return f"That's {result} {m.group(3)}."


def looks_like_math(text: str) -> bool:
    """Gate for whether calc is worth trying at all.

    Kept in step with _clean_expression: this listed only the spelled-out
    operators, so "15% of 240" and "sqrt 169" were not even offered to the
    calculator that (now) understands them. A gate narrower than the parser
    behind it is a silent capability loss.
    """
    t = text.lower()
    if re.search(r"\d\s*[\+\-\*/x]\s*\d", t):
        return True
    # An operator WORD only counts alongside an actual number. Without that,
    # adding "squared" here claimed "the volume of a cylinder is pi r squared
    # h" -- a description of a formula, not a sum to evaluate. The corpus
    # keeps that phrase precisely because it has the mathematical vocabulary
    # and none of the intent.
    if re.search(r"\d", t) and re.search(
            r"\b(plus|minus|times|divided by|multiplied by|"
            r"square root|sqrt|percent|squared|cubed|"
            r"to the power of)\b", t):
        return True
    # "15% of 240", "20% off 50", "what is 30%"
    if re.search(r"\d\s*%", t):
        return True
    return False

