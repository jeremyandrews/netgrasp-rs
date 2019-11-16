pub const NETGRASP_TITLE_TEMPLATE: &str = "[netgrasp] {{event}}: {{name}}";

pub const NETGRASP_TEXT_TEMPLATE: &str = "{{notification}}:
 * {{name}} {{vendor}}
 * ip: {{ip}} [{{mac}}]
 * interface: {{interface}}
 * previously seen: {{previously_seen}}
 * first seen: {{first_seen}}
 * recently seen: {{recently_seen}}

In the past 24 hours, this device talked to {{devices_talked_to_count_string}}:
{{#each devices_talked_to as |device| ~}}
 * {{device.name}} [{{device.count_string}}]
{{/each~}}

--
Email generated by the Netgrasp passive network observation tool.
https://github.com/jeremyandrews/netgrasp";

pub const NETGRASP_HTML_TEMPLATE: &str = r#"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional //EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<HTML lang={{lang}}>
<HEAD></HEAD>
<BODY>
  <P>{{notification}}:<UL>
    <LI>{{name}} <EM>{{vendor}}</EM>
    <LI>ip: {{ip}} [{{mac}}]</LI>
    <LI>interface: {{interface}}</LI>
    <LI>previously seen: {{previously_seen}}</LI>
    <LI>first seen: {{first_seen}}</LI>
    <LI>recently seen: {{recently_seen}}</LI>
  </UL></p>
  <P>In the past 24 hours, this device talked to {{devices_talked_to_count_string}}:<UL>
    {{#each devices_talked_to as |device| ~}}
    <LI>{{device.name}} [{{device.count_string}}]</LI>
    {{/each~}}
  </UL></P>
  <DIV ID="footer">
    <HR />
    <P><SMALL><EM>Email generated by the <A HREF="https://github.com/jeremyandrews/netgrasp">Netgrasp</A> passive network observation tool.</EM></SMALL></P>
  </DIV>
</BODY>
</HTML>"#;
