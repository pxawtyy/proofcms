<%@ Page Language="C#" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    Response.ContentType = "text/plain";
    Response.Write("USER=" + User.Identity.Name);
}
</script>
