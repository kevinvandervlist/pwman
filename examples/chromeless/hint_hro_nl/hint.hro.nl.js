const url = require("url");
Components.utils.import("resource://gre/modules/ctypes.jsm");

$(document).ready(function() {
    $("#content").attr("src", "https://hint.hro.nl");
});

function fill() {
    // open libpwman library
    var libpwman = ctypes.open("/home/kevin/software/pwman/libpwman/libpwman.so");

    // Declare the 2 functions we need.
    var getuser = libpwman.declare("pwman_getUser", 
				   ctypes.default_abi, 
				   ctypes.char.ptr
				  );

    var getpass = libpwman.declare("pwman_getPass", 
				   ctypes.default_abi, 
				   ctypes.char.ptr
				  );

    // Declare the return types. 
    var user = ctypes.char.ptr;
    var pass = ctypes.char.ptr;

    // Retrieve the data. 
    user = getuser();
    pass = getpass();

    // Retrieve the DOM items we need to set the val's to. 
    var cdoc = document.getElementById('content').contentDocument;
    var username = cdoc.getElementById('username');
    var password = cdoc.getElementById('password');
    
    // Use readstring() because it's a C-str 
    username.value = user.readString();
    password.value = pass.readString();

    // Close the library handle.
    libpwman.close();
}