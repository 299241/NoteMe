var registrationForm = document.getElementById("register");

registrationForm.addEventListener("submit", function (event) {
  let password = document.getElementById("password");
  let passwordRepeat = document.getElementById("password-repeat");
  let passwordConfirm = document.getElementById("password-confirm");

  if (password.value != passwordRepeat.value) {
    event.preventDefault();
    password.classList.add("is-invalid");
    passwordRepeat.classList.add("is-invalid");
    passwordConfirm.innerHTML = "Wprwadzone hasła nie są identyczne!";
  } else {
    password.classList.remove("is-invalid");
    passwordRepeat.classList.remove("is-invalid");
    passwordConfirm.innerHTML = "";
  }
});
