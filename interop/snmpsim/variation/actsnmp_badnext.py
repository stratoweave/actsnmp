#
# snmpsim variation module for the actsnmp interop lab: broken GETNEXT ordering.
#
# Record syntax (snmprec):
#   <oid>|2:actsnmp_badnext|target=<oid>,value=<int>
#   <oid>|2:actsnmp_badnext|target=self,value=<int>
#
# GET <oid>            -> <oid> = value  (normal)
# GETNEXT/GETBULK that lands on <oid>
#     target=<oid2>    -> answers with <oid2> (lexicographically SMALLER than the
#                         request -> "OID not increasing" for walking managers)
#     target=self      -> answers with the very OID that was requested
#                         (equal, i.e. not increasing either)
#
# The globals moduleContext / recordContext / agentContext are injected by
# snmpsim.
from pyasn1.type import univ


def init(**context):
    pass


def _settings(value):
    if "settings" not in recordContext:  # noqa: F821 - injected by snmpsim
        s = {}
        for item in value.split(","):
            if "=" in item:
                k, v = item.split("=", 1)
                s[k.strip()] = v.strip()
        recordContext["settings"] = s  # noqa: F821
    return recordContext["settings"]  # noqa: F821


def variate(oid, tag, value, **context):
    if not context["nextFlag"] and not context["exactMatch"]:
        return context["origOid"], tag, context["errorStatus"]

    settings = _settings(value)

    if context["setFlag"]:
        # read-only
        return context["origOid"], tag, context["errorStatus"]

    val = settings.get("value", "0")

    if context["nextFlag"]:
        target = settings.get("target", "self")
        if target == "self":
            return context["origOid"], tag, val
        return univ.ObjectIdentifier(target), tag, val

    return oid, tag, val


def shutdown(**context):
    pass
