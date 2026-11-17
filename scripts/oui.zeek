# Optional administrator-supplied IEEE MA-L CSV, read only via the Input Framework.
# No registry is bundled, downloaded, or inferred from a locally administered MAC.
@ifndef (WiFiTelemetry::oui_csv)
@load base/frameworks/input
@load base/frameworks/input/readers/raw
module WiFiTelemetry;
export {
    const oui_csv: string = "" &redef;
    const oui_max_entries: count = 65536 &redef;
    const oui_max_record_bytes: count = 65536 &redef;
    const oui_max_input_bytes: count = 16777216 &redef;
    global oui_vendor_hint: function(prefix: string): string;
    # A policy can use this signal to monitor readiness or gate offline replay.
    global oui_load_finished: event(success: bool);
}

type OUILine: record { line: string; };
type CSVState: record {
    fields: vector of string &default=vector();
    field: string &default="";
    quoted: bool &default=F;
    after_quote: bool &default=F;
    at_start: bool &default=T;
    bytes: count &default=0;
};
global csv_state=CSVState();
global oui_header: vector of string=vector();
global oui_columns: table[string] of count=table();
global oui_pending: table[string] of set[string]=table();
global oui_vendors: table[string] of string=table();
global oui_ready=F;
global oui_failed=F;
global oui_signaled=F;
global oui_input_bytes: count=0;
global oui_first_line=T;

function oui_vendor_hint(prefix: string): string
    { return oui_ready && prefix in oui_vendors ? oui_vendors[prefix] : ""; }

function oui_fail(message: string)
    {
    if ( oui_failed ) return;
    oui_failed=T; oui_ready=F; oui_pending=table(); oui_vendors=table();
    Reporter::warning(fmt("WiFiTelemetry: IEEE CSV vendor enrichment disabled: %s",message));
    if ( ! oui_signaled ) { oui_signaled=T; event oui_load_finished(F); }
    }

function csv_record(fields: vector of string)
    {
    if ( |oui_header| == 0 )
        {
        oui_header=fields;
        for ( i in fields )
            {
            if ( fields[i] in oui_columns ) { oui_fail("duplicate CSV header"); return; }
            oui_columns[fields[i]]=i;
            }
        if ( "Registry" !in oui_columns || "Assignment" !in oui_columns ||
             "Organization Name" !in oui_columns || "Organization Address" !in oui_columns )
            oui_fail("expected the original IEEE CSV header: Registry,Assignment,Organization Name,Organization Address");
        return;
        }
    if ( |fields| != |oui_header| ) { oui_fail("CSV row does not match the header"); return; }
    if ( fields[oui_columns["Registry"]] != "MA-L" ) return;
    local assignment=to_lower(fields[oui_columns["Assignment"]]);
    local name=fields[oui_columns["Organization Name"]];
    if ( ! (assignment == /^[0-9a-f]{6}$/) || name == "" )
        { oui_fail("invalid MA-L assignment or empty organization name"); return; }
    if ( to_count(assignment[:2],16)%4 != 0 ) return;
    local prefix=fmt("%s:%s:%s",assignment[:2],assignment[2:4],assignment[4:6]);
    if ( prefix !in oui_pending )
        {
        if ( |oui_pending| >= oui_max_entries ) { oui_fail("prefix capacity exceeded"); return; }
        oui_pending[prefix]=set();
        }
    if ( |oui_pending[prefix]| >= 16 && name !in oui_pending[prefix] )
        { oui_fail("too many organization names for one prefix"); return; }
    add oui_pending[prefix][name];
    }

# Raw Input records preserve CSV quoting; the ASCII reader's comma separator
# alone is not a CSV parser. State spans lines for quoted multiline fields.
event oui_line(desc: Input::EventDescription, kind: Input::Event, value: OUILine)
    {
    if ( oui_failed || kind != Input::EVENT_NEW ) return;
    local line=value$line;
    oui_input_bytes+=|line|+1;
    if ( oui_input_bytes > oui_max_input_bytes ) { oui_fail("input byte limit exceeded"); return; }
    if ( oui_first_line )
        {
        oui_first_line=F;
        if ( |line| >= 3 && line[:3] == "\xef\xbb\xbf" ) line=line[3:];
        }
    if ( |line| > 0 && line[|line|-1:] == "\r" ) line=line[:|line|-1];
    if ( |line| == 0 && csv_state$bytes == 0 ) return;
    csv_state$bytes+=|line|+1;
    if ( csv_state$bytes > oui_max_record_bytes ) { oui_fail("CSV record byte limit exceeded"); return; }
    local i: count=0;
    while ( i < |line| )
        {
        local ch=line[i:i+1]; ++i;
        if ( csv_state$quoted )
            {
            if ( ch == "\"" ) { csv_state$quoted=F; csv_state$after_quote=T; }
            else csv_state$field+=ch;
            }
        else if ( csv_state$after_quote && ch == "\"" )
            { csv_state$field+="\""; csv_state$quoted=T; csv_state$after_quote=F; }
        else if ( ch == "," )
            {
            csv_state$fields[|csv_state$fields|]=csv_state$field;
            csv_state$field=""; csv_state$at_start=T; csv_state$after_quote=F;
            }
        else if ( ch == "\"" && csv_state$at_start && ! csv_state$after_quote )
            { csv_state$quoted=T; csv_state$at_start=F; }
        else if ( csv_state$after_quote || ch == "\"" )
            { oui_fail("invalid CSV quoting"); return; }
        else { csv_state$field+=ch; csv_state$at_start=F; }
        }
    if ( csv_state$quoted ) { csv_state$field+="\n"; return; }
    csv_state$fields[|csv_state$fields|]=csv_state$field;
    csv_record(csv_state$fields); csv_state=CSVState();
    }

event oui_input_error(desc: Input::EventDescription, message: string, level: Reporter::Level)
    {
    if ( level != Reporter::INFO ) oui_fail(message);
    }

event Input::end_of_data(name: string, source: string)
    {
    if ( name != "wifi-ieee-oui" || oui_failed ) return;
    if ( csv_state$bytes > 0 || |oui_header| == 0 )
        { oui_fail("empty file or unterminated quoted CSV record"); return; }
    # Publish once the entire file is valid; a partial read never supplies hints.
    local complete: table[string] of string=table();
    for ( prefix in oui_pending )
        {
        local names: vector of string=vector();
        for ( organization in oui_pending[prefix] ) names[|names|]=organization;
        names=sort(names,strcmp);
        local combined="";
        for ( i in names ) combined+=(i == 0 ? "" : " | ")+names[i];
        complete[prefix]=combined;
        }
    oui_vendors=complete; oui_pending=table(); oui_ready=T;
    if ( ! oui_signaled ) { oui_signaled=T; event oui_load_finished(T); }
    }

event zeek_init() &priority=10
    {
    if ( oui_csv == "" ) return;
    if ( oui_max_entries == 0 || oui_max_record_bytes == 0 || oui_max_input_bytes == 0 )
        { oui_fail("CSV limits must be positive"); return; }
    # The raw reader can execute a source ending in '|'. Accept file paths only.
    if ( /\|/ in oui_csv || /\x00/ in oui_csv )
        { oui_fail("oui_csv must be a local file path, not a command source"); return; }
    if ( ! Input::add_event([$source=oui_csv,$name="wifi-ieee-oui",$reader=Input::READER_RAW,
          $mode=Input::MANUAL,$fields=OUILine,$ev=oui_line,$error_ev=oui_input_error,
          $config=table(["record_separator"]="\n")]) ) oui_fail("could not create CSV input stream");
    }
@endif
