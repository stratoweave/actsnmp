/*
 * mibwalk: dump net-snmp's parsed view of MIB modules as JSON lines.
 *
 *   mibwalk [-M DIRS] [-P MIBOPTS] [-a] [-d] MODULE...   (MODULE "ALL" = every module in DIRS, implies -a)
 *
 * Loads MODULE... (and their imports) with libnetsnmp's MIB parser, exactly
 * like "snmptranslate -M DIRS -m MODULE", then prints one JSON object per
 * tree node that belongs to one of the named modules (-a: every node in the
 * tree), in OID order. This is the structured equivalent of
 * "snmptranslate -Td" for every node. MIB parse errors/warnings go to stderr
 * unchanged (same messages as snmptranslate). -P takes snmptranslate's -P
 * options (e.g. -Pu, -Pw, -PW). -d adds DESCRIPTION texts.
 *
 * Node fields (omitted when empty): oid, name, module, modules (when >1
 * module defines the node), kind (net-snmp's macro/type code as text), tc
 * (textual convention name), access, status, hint, units, enums
 * [[value,label],...], ranges [[low,high],...], indexes [[label,implied],...],
 * augments, varbinds [...], defval, description.
 * The last line is {"_loaded": {MODULE: true|false, ...}}.
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int want_all = 0, want_descr = 0;
static int nmods = 0;
static int *modids = NULL;

static void jstr(const char *s)
{
    const unsigned char *p;
    putchar('"');
    for (p = (const unsigned char *) s; p && *p; p++) {
        switch (*p) {
        case '"': fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            /* bytes >= 0x80 are emitted as latin-1 code points: always valid JSON */
            if (*p < 0x20 || *p >= 0x7f)
                printf("\\u%04x", *p);
            else
                putchar(*p);
        }
    }
    putchar('"');
}

static const char *kind_name(int t)
{
    switch (t) {
    case TYPE_OTHER: return "other";
    case TYPE_OBJID: return "OBJECT IDENTIFIER";
    case TYPE_OCTETSTR: return "OCTET STRING";
    case TYPE_INTEGER: return "INTEGER";
    case TYPE_NETADDR: return "NetworkAddress";
    case TYPE_IPADDR: return "IpAddress";
    case TYPE_COUNTER: return "Counter32";
    case TYPE_GAUGE: return "Gauge32";
    case TYPE_TIMETICKS: return "TimeTicks";
    case TYPE_OPAQUE: return "Opaque";
    case TYPE_NULL: return "NULL";
    case TYPE_COUNTER64: return "Counter64";
    case TYPE_BITSTRING: return "BITS";
    case TYPE_NSAPADDRESS: return "NsapAddress";
    case TYPE_UINTEGER: return "UInteger32";
    case TYPE_UNSIGNED32: return "Unsigned32";
    case TYPE_INTEGER32: return "Integer32";
    case TYPE_TRAPTYPE: return "TRAP-TYPE";
    case TYPE_NOTIFTYPE: return "NOTIFICATION-TYPE";
    case TYPE_OBJGROUP: return "OBJECT-GROUP";
    case TYPE_NOTIFGROUP: return "NOTIFICATION-GROUP";
    case TYPE_MODID: return "MODULE-IDENTITY";
    case TYPE_AGENTCAP: return "AGENT-CAPABILITIES";
    case TYPE_MODCOMP: return "MODULE-COMPLIANCE";
    case TYPE_OBJIDENTITY: return "OBJECT-IDENTITY";
    default: return NULL;
    }
}

static const char *access_name(int a)
{
    switch (a) {
    case MIB_ACCESS_READONLY: return "read-only";
    case MIB_ACCESS_READWRITE: return "read-write";
    case MIB_ACCESS_WRITEONLY: return "write-only";
    case MIB_ACCESS_NOACCESS: return "not-accessible";
    case MIB_ACCESS_NOTIFY: return "accessible-for-notify";
    case MIB_ACCESS_CREATE: return "read-create";
    default: return NULL;
    }
}

static const char *status_name(int s)
{
    switch (s) {
    case MIB_STATUS_MANDATORY: return "mandatory";
    case MIB_STATUS_OPTIONAL: return "optional";
    case MIB_STATUS_OBSOLETE: return "obsolete";
    case MIB_STATUS_DEPRECATED: return "deprecated";
    case MIB_STATUS_CURRENT: return "current";
    default: return NULL;
    }
}

static int selected(struct tree *tp)
{
    int i, j;
    if (want_all)
        return 1;
    for (i = 0; i < nmods; i++) {
        if (modids[i] < 0)
            continue;
        if (tp->modid == modids[i])
            return 1;
        for (j = 0; j < tp->number_modules; j++)
            if (tp->module_list && tp->module_list[j] == modids[i])
                return 1;
    }
    return 0;
}

static void print_oid(struct tree *tp)
{
    u_long sub[MAX_OID_LEN];
    int n = 0, i;
    for (; tp && n < MAX_OID_LEN; tp = tp->parent)
        sub[n++] = tp->subid;
    for (i = n - 1; i >= 0; i--)
        printf(i == n - 1 ? "%lu" : ".%lu", sub[i]);
}

static void print_node(struct tree *tp)
{
    char buf[1024];
    const char *s;
    int first, i;

    fputs("{\"oid\":\"", stdout);
    print_oid(tp);
    fputs("\",\"name\":", stdout);
    jstr(tp->label);
    buf[0] = 0;
    module_name(tp->modid, buf);
    fputs(",\"module\":", stdout);
    jstr(buf);
    if (tp->number_modules > 1 && tp->module_list) {
        fputs(",\"modules\":[", stdout);
        for (i = 0; i < tp->number_modules; i++) {
            buf[0] = 0;
            module_name(tp->module_list[i], buf);
            if (i)
                putchar(',');
            jstr(buf);
        }
        putchar(']');
    }
    s = kind_name(tp->type);
    if (s) {
        fputs(",\"kind\":", stdout);
        jstr(s);
    } else
        printf(",\"kind\":\"type-%d\"", tp->type);
    if (tp->tc_index >= 0 && (s = get_tc_descriptor(tp->tc_index))) {
        fputs(",\"tc\":", stdout);
        jstr(s);
    }
    if ((s = access_name(tp->access))) {
        fputs(",\"access\":", stdout);
        jstr(s);
    }
    if ((s = status_name(tp->status))) {
        fputs(",\"status\":", stdout);
        jstr(s);
    }
    if (tp->hint) {
        fputs(",\"hint\":", stdout);
        jstr(tp->hint);
    }
    if (tp->units) {
        fputs(",\"units\":", stdout);
        jstr(tp->units);
    }
    if (tp->enums) {
        struct enum_list *ep;
        fputs(",\"enums\":[", stdout);
        for (first = 1, ep = tp->enums; ep; ep = ep->next, first = 0) {
            printf("%s[%d,", first ? "" : ",", ep->value);
            jstr(ep->label);
            putchar(']');
        }
        putchar(']');
    }
    if (tp->ranges) {
        struct range_list *rp;
        fputs(",\"ranges\":[", stdout);
        for (first = 1, rp = tp->ranges; rp; rp = rp->next, first = 0)
            printf("%s[%d,%d]", first ? "" : ",", rp->low, rp->high);
        putchar(']');
    }
    if (tp->indexes) {
        struct index_list *ip;
        fputs(",\"indexes\":[", stdout);
        for (first = 1, ip = tp->indexes; ip; ip = ip->next, first = 0) {
            fputs(first ? "[" : ",[", stdout);
            jstr(ip->ilabel);
            printf(",%s]", ip->isimplied ? "true" : "false");
        }
        putchar(']');
    }
    if (tp->augments) {
        fputs(",\"augments\":", stdout);
        jstr(tp->augments);
    }
    if (tp->varbinds) {
        struct varbind_list *vp;
        fputs(",\"varbinds\":[", stdout);
        for (first = 1, vp = tp->varbinds; vp; vp = vp->next, first = 0) {
            if (!first)
                putchar(',');
            jstr(vp->vblabel);
        }
        putchar(']');
    }
    if (tp->defaultValue) {
        fputs(",\"defval\":", stdout);
        jstr(tp->defaultValue);
    }
    if (want_descr && tp->description) {
        fputs(",\"description\":", stdout);
        jstr(tp->description);
    }
    fputs("}\n", stdout);
}

/* children are kept in a linked list in arbitrary order: sort by subid, label */
static int cmp_tree(const void *a, const void *b)
{
    const struct tree *x = *(struct tree * const *) a, *y = *(struct tree * const *) b;
    if (x->subid != y->subid)
        return x->subid < y->subid ? -1 : 1;
    return strcmp(x->label ? x->label : "", y->label ? y->label : "");
}

static void walk(struct tree *first)
{
    struct tree *tp, **v;
    int n = 0, i;
    for (tp = first; tp; tp = tp->next_peer)
        n++;
    if (!n)
        return;
    v = malloc(n * sizeof(*v));
    for (i = 0, tp = first; tp; tp = tp->next_peer)
        v[i++] = tp;
    qsort(v, n, sizeof(*v), cmp_tree);
    for (i = 0; i < n; i++) {
        if (selected(v[i]))
            print_node(v[i]);
        walk(v[i]->child_list);
    }
    free(v);
}

int main(int argc, char **argv)
{
    int c, i;
    char *dirs = NULL;
    /* like snmptranslate: report MIB parse errors (-Pe toggles them off) */
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_ERRORS, 1);
    while ((c = getopt(argc, argv, "M:P:ad")) != -1) {
        switch (c) {
        case 'M': dirs = optarg; break;
        case 'P':
            if (snmp_mib_toggle_options(optarg)) {
                fprintf(stderr, "mibwalk: unknown -P option in %s\n", optarg);
                return 2;
            }
            break;
        case 'a': want_all = 1; break;
        case 'd': want_descr = 1; break;
        default:
            fprintf(stderr, "usage: mibwalk [-M DIRS] [-P MIBOPTS] [-a] [-d] MODULE...\n");
            return 2;
        }
    }
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_READ_CONFIGS, 1);
    if (dirs)
        setenv("MIBDIRS", dirs, 1);
    setenv("MIBS", "", 1);
    snmp_enable_stderrlog();
    netsnmp_init_mib();
    nmods = argc - optind;
    modids = calloc(nmods > 0 ? nmods : 1, sizeof(int));
    for (i = 0; i < nmods; i++) {
        if (strcmp(argv[optind + i], "ALL") == 0) {     /* like -m ALL */
            read_all_mibs();
            modids[i] = -1;
            want_all = 1;
            continue;
        }
        read_module(argv[optind + i]);
        modids[i] = which_module(argv[optind + i]);
    }
    walk(get_tree_head());
    fputs("{\"_loaded\":{", stdout);
    for (i = 0; i < nmods; i++) {
        if (i)
            putchar(',');
        jstr(argv[optind + i]);
        fputs(modids[i] >= 0 ? ":true" : ":false", stdout);
    }
    fputs("}}\n", stdout);
    return 0;
}
