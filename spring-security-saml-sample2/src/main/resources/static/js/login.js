$(function (){

  // login
  $('.btn-login').on('click', function (event){
    event.preventDefault();
    console.log("login");
    $('#login').submit();
  });

});