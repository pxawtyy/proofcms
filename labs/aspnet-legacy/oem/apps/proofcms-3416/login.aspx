<%@ Page Language="C#" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    if (Request.HttpMethod == "POST")
    {
        string user = Request.Form["user"];
        string pass = Request.Form["pass"];
        if (user != null && pass == "lab-password")
        {
            FormsAuthentication.SetAuthCookie(user, false);
            Response.Redirect("protected.aspx");
        }
    }
}
</script>
<!DOCTYPE html>
<html>
<body>
<form method="post" action="login.aspx">
  <input name="user" />
  <input name="pass" type="password" />
  <input type="submit" value="Login" />
</form>
</body>
</html>
