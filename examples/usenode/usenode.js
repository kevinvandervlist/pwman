// "usenode"; a usenet + pwmand demonstration
// Import the necessary stuff
var NNTP = require('./nntp'), inspect = require('util').inspect, conn;
var ffi = require('./lib/ffi');

// Prepare the user 
var libpwman_u = new ffi.Library("/home/kevin/software/pwman/libpwman/libpwman", { "pwman_getUser": [ "string", [ ] ] });

// And the pass 
var libpwman_p = new ffi.Library("/home/kevin/software/pwman/libpwman/libpwman", {"pwman_getPass": [ "string", [ ] ] });

function die(e) {
    console.log('Error!');
    console.error(e);
    process.exit(1);
}

conn = new NNTP({
    //host: 'newsreader4.eweka.nl'
    host: process.argv[2]
});
conn.on('connect', function() {
    conn.auth(libpwman_u.pwman_getUser(), libpwman_p.pwman_getPass(), function(e) {
	if (e) die(e);
	doActions();
    });
});
conn.on('error', function(err) {
    console.error('Error: ' + inspect(err));
});
conn.connect();

function doActions() {
    var groups = ['comp.os.linux.announce'];
  conn.groupsDescr(groups, function(e, em) {
    if (e) die(e);
    em.on('description', function(name, description) {
      console.log(name + ': ' + description);
    });
    em.on('end', function() {
      console.log('End of descriptions');
      conn.end();
    });
  });
};
