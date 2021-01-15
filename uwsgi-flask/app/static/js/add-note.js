$("#type").change(function () {
  switch ($(this).val()) {
    case "private-note":
      $("#secret-password").hide();
      $("#shared-to").hide();
      break;
    case "encrypt-note":
      $("#secret-password").show();
      $("#shared-to").hide();
      break;
    case "public-note":
      $("#secret-password").hide();
      $("#shared-to").hide();
      break;
    case "shared-note":
      $("#secret-password").hide();
      $("#shared-to").show();
      break;
  }
});
$("#type").trigger("change");
