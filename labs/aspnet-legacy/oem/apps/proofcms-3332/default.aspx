<%@ Page Language="C#" %>
<%@ Register Assembly="System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" Namespace="System.Web.UI" TagPrefix="asp" %>
<!DOCTYPE html>
<html>
<body>
<form id="form1" runat="server">
  <asp:ScriptManager ID="ScriptManager1" runat="server">
    <Scripts>
      <asp:ScriptReference Name="MicrosoftAjax.js" />
    </Scripts>
  </asp:ScriptManager>
  <asp:TextBox ID="TextBox1" runat="server"></asp:TextBox>
  <asp:RequiredFieldValidator ID="RequiredFieldValidator1" runat="server"
    ControlToValidate="TextBox1" ErrorMessage="Required"></asp:RequiredFieldValidator>
  <asp:Button ID="Button1" runat="server" Text="Submit" />
</form>
</body>
</html>
