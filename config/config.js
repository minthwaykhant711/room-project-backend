const mysql = require("mysql2");
const con = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'room_reserve_test'
});


module.exports = con;