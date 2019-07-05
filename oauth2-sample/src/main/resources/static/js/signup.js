$(function (){
  $('.btn-register').on('click', function (event){
    event.preventDefault();
    console.log("registerByEmail");
    var postBody = $('#signupForm').serialize();
    console.log(postBody);

    $.ajax({
      type: 'post',
      async: false,
      url: 'signup',
      data: postBody,
    }).done(function (){
      alert('SUCCESS');
      location.href = '../login'
    }).fail(function (xhr, status){
      console.log(xhr);
      alert("ERROR:" + status);
    });

  });


});

