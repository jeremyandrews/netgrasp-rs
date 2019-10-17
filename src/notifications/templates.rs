pub const NETGRASP_TEXT_TEMPLATE: &str = "{{notification}}:
 * {{name}}
 * ip: {{ip}} [{{mac}}]
 * previously seen: {{previously_seen}}
 * first seen: {{first_seen}}
 * recently seen: {{times}}

--
Email generated by the Netgrasp passive network observation tool.
https://github.com/jeremyandrews/netgrasp";

pub const NETGRASP_HTML_TEMPLATE: &str = r#"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional //EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<HTML lang={{lang}}>
<HEAD></HEAD>
<BODY>
  {{notification}}: 
  <UL>
    <LI>{{name}}</LI>
    <LI>ip: {{ip}} [{{mac}}]</LI>
    <LI>previously seen: {{previously_seen}}</LI>
    <LI>first seen: {{first_seen}}</LI>
    <LI>recently seen: {{times}}</LI>
  </UL>
  <DIV ID="footer">
    <HR />
    <P><SMALL><EM>Email generated by the <A HREF="https://github.com/jeremyandrews/netgrasp">Netgrasp</A> passive network observation tool.</EM></SMALL></P>
  </DIV>
</BODY>
</HTML>"#;