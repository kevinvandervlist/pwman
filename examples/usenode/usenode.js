// "usenode"; a usenet + pwmand demonstration

var NNTP = require('./nntp'), inspect = require('util').inspect, conn;

function die(e) {
    console.log('Error!');
    console.error(e);
    process.exit(1);
}

//conn = new NNTPClient({
conn = new NNTP({
    host: 'newsreader4.eweka.nl'
});
conn.on('connect', function() {
    conn.auth('user', 'pass', function(e) {
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
