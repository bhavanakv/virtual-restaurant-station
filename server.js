let express = require("express");
var cors = require("cors");
var mysql = require("mysql");
let app = express();
let bodyParser = require("body-parser");
var bcrypt = require("bcrypt");
var dotenv = require("dotenv");
var jwt = require("jsonwebtoken");
let compression = require("compression");
let open = require("open");
let moment = require("moment");
let helmet = require("helmet");
let formidable = require("formidable");
let fs = require("fs");

dotenv.config();
app.use(helmet()); // Prevents XSS attacks
app.use(compression());
app.use(express.static("public"));
app.use("/users", express.static("./users"));
app.use("/rusers", express.static("./rusers"));
app.use(bodyParser({extended: true}));
app.use(cors());;

var con;
function connection() {
    con = mysql.createConnection({
        host:'localhost',
        user:'root',
        password:'root123',
        database:'project'
    }); 
    con.connect(function(err) {
        if(err) throw err;
            console.log("Connected!");
    }); 
}

//user login
app.post("/api/login",function(req,res) {
    let {username,password}=req.body;
    res.writeHead(200,{"Content-Type": "application/json"});
    connection();
    con.query("select * from user where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(!results.length) {
            res.end(JSON.stringify({success:false, message:"User does not exist"}));
            return;
        }
        bcrypt.compare(password,results[0].password,(err,correct)=>{
            if(err) throw error;
            if(!correct) 
                res.end(JSON.stringify({success: false,message: "Username and password don't match"}));
            else {
                let user = {name: results[0].name, username: results[0].username};
                let token = jwt.sign(user, process.env.SESSION_SECRET, {
                    expiresIn: "1 day"
                });
                res.end(JSON.stringify({success: true, message: "Login success!", token}));
            }
        });
    });
});

//restaurant co-ordinator login
app.post("/api/rlogin",function(req,res) {
    let {username,password}=req.body;
    res.writeHead(200,{"Content-Type": "application/json"});
    connection();
    con.query("select * from restaurant where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(!results.length) {
            res.end(JSON.stringify({success:false, message:"User does not exist"}));
            return;
        }
        bcrypt.compare(password,results[0].password,(err,correct)=>{
            if(err) throw error;
            if(!correct) 
                res.end(JSON.stringify({success: false,message: "Username and password don't match"}));
            else {
                let user = {name: results[0].name, username: results[0].username};
                let token = jwt.sign(user, process.env.SESSION_SECRET, {
                    expiresIn: "1 day"
                });
                res.end(JSON.stringify({success: true, message: "Login success!", token}));
            }
                
        });
    });
});

//party hall co-ordinator login
app.post("/api/plogin",function(req,res) {
    let {username,password}=req.body;
    var correct,yes;
    res.writeHead(200,{"Content-Type": "application/json"});
    connection();
    con.query("select * from party where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(!results.length) {
            res.end(JSON.stringify({success:false, message:"User does not exist"}));
            return;
        }
        bcrypt.compare(password,results[0].password,(err,correct)=>{
            if(err) throw error;
            if(!correct) 
                res.end(JSON.stringify({success: false,message: "Username and password don't match"}));
            else {
                let user = {name: results[0].name, username: results[0].username};
                let token = jwt.sign(user, process.env.SESSION_SECRET, {
                    expiresIn: "1 day"
                });
                res.end(JSON.stringify({success: true, message: "Login success!", token}));
            }
                
        });
    });
});

//user registration
app.post("/api/signup",function(req,res) {
    let {name,username,password,email,choice1}=req.body;
    res.writeHead(200, {"Content-Type": "application/json"});

    let form = new formidable.IncomingForm();
    form.parse(req, (err, fields, files) => {
        if (err) {
            res.end(JSON.stringify({success: false, message: "Couldn't parse request"}));
            return;
        }

        let {name, username, password, email, choice1} = fields;
        let {dp} = files;

        if (!fs.existsSync("./users"))
            fs.mkdirSync("./users");
        if (!fs.existsSync(`./users/${username}`))
            fs.mkdirSync(`./users/${username}`);
        
        fs.rename(dp.path, `./users/${username}/${dp.name}`, (e) => {
            if (e) {
                res.end(JSON.stringify({success: false, message: "Couldn't upload DP"}));
                return;
            }

            connection();
            con.query("select * from user where binary username=?",[username],function(err,results) {
                if(err) throw err;
                if(results.length) { 
                    res.end(JSON.stringify({success:false, message:"Username exists"}));
                    return;
                }
                bcrypt.hash(password,10,(err,hash)=> {
                    if(err) throw err;
                    console.log(hash);
                    con.query("insert into user values(?,?,?,?,?,?)",[username,hash,name,email,choice1,`./users/${username}/${dp.name}`],(err) => {
                        if(err) {
                        res.end(JSON.stringify({success:false, message:"Unknown error occurred.Try again."}));
                        }
                        res.end(JSON.stringify({success:true, message:"User registered successfully"}));
                    });
                });
            });
        });
    });
});

//restaurant co-ordinator registration
app.post("/api/rsignup",function(req,res) {
    res.writeHead(200, {"Content-Type": "application/json"});

    let form = new formidable.IncomingForm();
    form.parse(req, (err, fields, files) => {
        if (err) throw err;

        let {name,username,password,location,type,table,otime,ctime}=fields;
        let {dp} = files;

        if (!fs.existsSync("./rusers"))
            fs.mkdirSync("./rusers");
        if (!fs.existsSync(`./rusers/${username}`))
            fs.mkdirSync(`./rusers/${username}`);
        
        fs.rename(dp.path, `./rusers/${username}/${dp.name}`, (e) => {
            if (e) {
                res.end(JSON.stringify({success: false, message: "Couldn't upload DP"}));
                return;
            }

            connection();
            let fotime = moment(otime, "h:mm A").format("H:mm");
            let fctime = moment(ctime, "h:mm A").format("H:mm");
            con.query("select * from restaurant where binary username=?",[username],function(err,results) {
                if(err) throw err;
                if(results.length) { 
                    res.end(JSON.stringify({success:false, message:"Username exists"}));
                    return;
                }
            bcrypt.hash(password,10,(err,hash)=> {
                if(err) throw err;
                console.log(hash);
                con.query("insert into restaurant values(?,?,?,?,?,?,?,?,?)",[username,hash,name,location,type,table,fotime,fctime, `./rusers/${username}/${dp.name}`],(err) => {
                    if(err) {
                       res.end(JSON.stringify({success:false, message:"Unknown error occurred.Try again."}));
                    }
                    res.end(JSON.stringify({success:true, message:"Registered successfully"}));
                    });
                });
            });
        });
    });
});

//party hall co-ordinator registration
app.post("/api/psignup",function(req,res) {
    let {name,username,password,location,amount}=req.body;
    res.writeHead(200, {"Content-Type": "application/json"});
    connection();
    con.query("select * from party where binary username=?",[username],function(err,results) {
        if(err) throw err;
        if(results.length) { 
            res.end(JSON.stringify({success:false, message:"Username exists"}));
            return;
        }
    bcrypt.hash(password,10,(err,hash)=> {
        if(err) throw err;
        console.log(hash);
        con.query("insert into party values(?,?,?,?,?)",[username,hash,name,location,amount],(err) => {
            if(err) {
               res.end(JSON.stringify({success:false, message:"Unknown error occurred.Try again."}));
            }
            res.end(JSON.stringify({success:true, message:"Registered successfully"}));
            });
        });
    });
});

//search restaurants 
app.post("/api/search",function(req,res) {
    let {type} = req.body;
    res.writeHead(200, {"Content-Type": "application/json"});
    console.log(type);
    connection();
    con.query("select name,location,dp,o_time,c_time from restaurant where type=?",[type],function(err,rows,fields) {
        if(err) throw err;
        if (!rows.length) {
            res.end(JSON.stringify({success:false, resto:"No restaurants"}));
            return;
        }
        console.log(rows);
        res.end(JSON.stringify({success: true, resto: rows}));
    }); 
     con.end();
});

//view reviews
app.get("/api/review",function(req,res) {
    res.writeHead(200, {"Content-Type": "application/json"});
    connection();
    con.query("select u.name as user,r.name as resto,u.dp as dp,comment,rating from user u,restaurant r,review r1 where u.username=r1.user and r.username=r1.ruser",function(err,rows,fields) {
        if(err) throw err;
        if (!rows.length) {
            res.end(JSON.stringify({success:false, rev:"No reviews added yet"}));
            return;
        }
        console.log(rows);
        res.end(JSON.stringify({success: true, rev: rows}));
    }); 
    con.end();
});

//search party halls
app.post("/api/psearch",function(req,res) { 
    let {choice} = req.body;
    res.writeHead(200, {"Content-Type": "application/json"});
    console.log(choice);
    connection(); 
    switch(choice) {
    case "1": con.query("select name,location,amount from party where amount<50000",function(err,rows,fields) {
            if(err) throw err;
            if (!rows.length) {
                res.end(JSON.stringify({success:false, par:"No party halls"}));
                return;
            }
            console.log(rows);
            res.end(JSON.stringify({success: true, par: rows}));
            }); 
            con.end();
            break;
    case "2": con.query("select name,location,amount from party where amount between 50000 and 100000",function(err,rows,fields) {
            if(err) throw err;
            if (!rows.length) {
                res.end(JSON.stringify({success:false, par:"No party halls"}));
                return;
            }
            console.log(rows);
            res.end(JSON.stringify({success: true, par: rows}));
            }); 
            con.end();
            break;
    case "3": con.query("select name,location,amount from party where amount between 100000 and 300000",function(err,rows,fields) {
            if(err) throw err;
            if (!rows.length) {
                res.end(JSON.stringify({success:false, par:"No party halls"}));
                return;
            }
            console.log(rows);
            res.end(JSON.stringify({success: true, par: rows}));
            }); 
            con.end();
            break;
    case "4":
            con.query("select name,location,amount from party where amount>300000",function(err,rows,fields) {
            if(err) throw err;
            if (!rows.length) {
                res.end(JSON.stringify({success:false, par:"No party halls"}));
                return;
            }
            console.log(rows);
            res.end(JSON.stringify({success: true, par: rows}));
            }); 
            con.end();
            break;
    }
});

//user details
app.post("/api/whoami",function(req,res) {
    res.writeHead(200, {"Content-Type": "application/json"});
    let {token} = req.body;
    console.log(token);
    jwt.verify(token, process.env.SESSION_SECRET, (err, decoded) => {
        console.log(decoded);
        if (err)
            res.end(JSON.stringify({success: false}));
        else {
            console.log(decoded);
            res.end(JSON.stringify({success: true, user: decoded}));
        }
    });
});

app.get("/api/user/:username", (req, res) => {
    connection();
    con.query("SELECT username, name, email, notify, dp FROM user WHERE username = ?", [req.params.username], (err, results) => {
        if (err) throw err;

        res.json(results[0]);
    })
});

app.get("/api/ruser/:username", (req, res) => {
    connection();
    con.query("SELECT dp FROM restaurant WHERE username = ?", [req.params.username], (err, results) => {
        if (err) throw err;

        res.json(results[0]);
    })
});

//view table reservations
app.post("/api/viewRes",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    let {username} = req.body;
    connection();
    let date = new Date().toISOString();
    console.log(date);
    con.query("select u.name as name,tables,code,d,t from reservation r,user u where r.username=u.username and ruser=? and datediff(d,now())=0",[username],function(err,row,fields){
        if(err) throw err;
        if(!row.length)
            res.end(JSON.stringify({success: false, reserve: "No reservations made yet"}));
        else    
            res.end(JSON.stringify({success: true, reserve: row}));
    });
});

//add offers
app.post("/api/add_offers",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    let {username,offer,promo} = req.body;
    connection();
    con.query("select * from offers where code=?",[promo],function(err,rows,fields){
        if(err) throw err;
        if(rows.length) {
            res.end(JSON.stringify({success:false, message:"Promo code has been used. Try again!"}));
            return;
        }
    });
    con.query("insert into offers values(?,?,?)",[username,offer,promo],(err,result)=>{
        if(err) 
            res.end(JSON.stringify({success:false, message:"Unknown error occurred. Try again!"}));
        else    
            res.end(JSON.stringify({success:true, message: "Offer has been added successfully!"}));
    });
});

//finding number of reservations
app.post("/api/delete_offers1",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    let {username,dpromo} = req.body;
    connection();
    con.query("select * from offers where code=? and ruser=?",[dpromo,username],function(err,rows,fields){
        if(err) throw err;
        if(!rows.length) {
            res.end(JSON.stringify({success:false, message:"No offer with this promo exists"}));
            return;
        }
    });
    con.query("select count(*) as total from reservation where code=? and datediff(d,now())>=0",[dpromo],function(err,results,fields){
        if(err) throw err;
        if(results[0].total==0)
            res.end(JSON.stringify({success:true,message:"There are no reservations with this promo code"}));
        else
            res.end(JSON.stringify({success:true,message:`There are ${results[0].total} reservations using this code.`}));
    });
});

//delete offers
app.post("/api/delete_offers2",function(req,res){
    res.writeHead(200,{"Content-Type": "application/json"});
    let {username,dpromo} = req.body;
    var name,msg;
    connection();
        con.query("select name from restaurant where username=?",[username],function(err1,results,fields){
            if(err1) throw err1;
            name = results[0].name;
            msg = "The offer with which you have reserved has been removed. Your reservation still holds but without offer. Sorry for the inconvinence";
            con.query("select username from reservation where code=?",[dpromo],(err,result,fields)=>{
                if(err) throw err;
                console.log(result);
                var i;
                for(i=0;i<result.length;i++) {
                    con.query("insert into notification values(?,?,?)",[result[i].username,name,msg],(err1,notify)=>{
                        if(err1) throw err1;
                    });
                }
                con.query("delete from offers where ruser=? and code=?",[username,dpromo],(err,results)=>{
                    if(err) throw err;
                if(i==result.length)
                    res.end(JSON.stringify({success:true,message:"Offer has been deleted successfully"}));  
                else
                    res.end(JSON.stringify({success:false,message:"Sorry couldn't send the notifications."}));              
            });
        });
    });
});

//view party hall reservations
app.post("/api/reserve",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    let {username} = req.body;
    connection();
    let date = new Date().toISOString();
    console.log(date);
    con.query("select u.name as name,d,t from p_reserve r,user u where r.username=u.username and puser=? and datediff(d,now())=0",[username],function(err,row,fields){
        if(err) throw err;
        if(!row.length)
            res.end(JSON.stringify({success: false, reserve: "No reservations made yet"}));
        else    
            res.end(JSON.stringify({success: true, reserve: row}));
    });
});

//view offers
app.get("/api/view_offers",function(req,res) {
    res.writeHead(200,{"Content-Type": "application/json"});
    connection();
    con.query("select * from offers",function(err,row,fields){
        if(err) throw err;
        if(!row.length)
            res.send(JSON.stringify({success:false, view:"No offers have been added yet"}));
        else
            res.end(JSON.stringify({success:true, view: row}));
    });
});

//add reviews
app.post("/api/add_review",function(req,res){
    res.writeHead(200,{"Content-Type":"application/json"});
    let {username,resto,comment,rating,location} = req.body;
    connection();
    let ruser;
    con.query("select * from restaurant where name=? and location=?",[resto,location],function(err,row,fields){
        if(err) throw err;
        if(!row.length) {
            res.end(JSON.stringify({success:false, message:"Error in the details of restaurant"}));
            return;
        }
        else {
            ruser = row[0].username;
            console.log(ruser);
            con.query("insert into review values(?,?,?,?)",[username,ruser,comment,rating],function(err,result){
                if(err) 
                    res.end(JSON.stringify({success:false, message:"Unknown error occurred. Try again."}));
                else
                    res.end(JSON.stringify({success:true, message:"Review has been added successfully!"}));
            });
        }
    });
});

//table booking
app.post("/api/tbook",function(req,res){
    res.writeHead(200,{"Content-Type":"application/json"});
    let {username,restaurant,date,time,tables,promo} = req.body;
    let fdate = moment(new Date(date)).format("YYYY-MM-DD");
    console.log(fdate);
    var ruser,available,table;
    let ftime = moment(time, "h:mm A").format("H:mm");
    connection(); 
    con.query("select username,tables from restaurant where name=?",[restaurant],function(err,row,fields){
        if(err) throw err;
        if(!row.length) {
            res.end(JSON.stringify({success:false, message:"Restaurant does not exist"}));
            return;
        }
        else {
            var flag=0;
            ruser = row[0].username;
            available = row[0].tables;
            con.query("select * from restaurant where username=? and timediff(o_time,?)<0 and timediff(c_time,?)>0",[ruser,ftime,ftime],function(err6,results,fields){
                if(err6) throw err6;
                if(!results.length) {
                    res.end(JSON.stringify({success:false,message: "Wrong time entered"}));
                    flag=1;
                    return;
                }
                else {
                    if(promo!="") {
                        con.query("select * from offers where code=? and ruser=?",[promo,ruser],function(err1,rows,fields){
                            if(err1) throw err1;
                            if(!rows.length) {
                                res.end(JSON.stringify({success:false,message: "Promo code not valid"}));
                                return;
                            }
                        });
                    }
                    con.query("select * from reservation where username=? and ruser=? and d=? and t=?",[username,ruser,fdate,ftime],function(err,row1,fields){
                        if(err) throw err;
                        if(row1.length) {
                            res.end(JSON.stringify({success:false,message: "Sorry, this slot has been booked already"}));
                            return;
                        }
                    });
                    con.query("call code_check(?,?,@total);",[promo,username],function(err,rows){
                        if(err) throw err;
                        else {
                            con.query("select @total as total",function(err3,rows){
                            if(err3) throw err3;
                            else if(rows[0].total>0 && promo!="") {
                                res.end(JSON.stringify({success:false, message:"Offer has been already used"}));
                            }
                            else {
                                con.query("select sum(tables) as total from reservation where d=? and t=? and ruser=?",[fdate,ftime,ruser],function(err4,r,fields){
                                if(err) throw err;
                                if(!r[0].total)
                                    table = 0;
                                else    
                                    table = r[0].total;
                                    tables = Number(tables);
                                    if(tables+table<=available) {
                                    if(promo!="") {
                                        if(flag!=1) {
                                        con.query("insert into reservation values(?,?,?,?,?,?)",[username,ruser,promo,tables,fdate,ftime],function(err2,result){
                                        if(err2)  {
                                            res.end(JSON.stringify({success:false,message: "Please check the date and time entered"}));
                                        }
                                        else    
                                            res.end(JSON.stringify({success:true,message: "Your table has been booked successfully!!"}));
                                        });
                                        }
                                    }           
                                    else {
                                        if(flag!=1) {
                                        con.query("insert into reservation values(?,?,NULL,?,?,?)",[username,ruser,tables,fdate,ftime],function(err2,result){
                                        if(err2) {
                                        res.end(JSON.stringify({success:false,message: "Please check the date and time entered"}));
                                        }
                                        else    
                                            res.end(JSON.stringify({success:true,message: "Your table has been booked successfully!!"}));
                                        });
                                        }
                                    }
                                }
                                else
                                    res.end(JSON.stringify({success:false,message:"Sorry, couldn't book because it was out of the limit."}));
            
                                }); 
                            }
                        }); 
                    }
                });
            }
            });
        }
    });
});


//party hall booking
app.post("/api/pbook",function(req,res){ 
    res.writeHead(200,{"Content-Type":"application/json"});
    let {username,hall,date,time} = req.body;
    let fdate = moment(new Date(date)).format("YYYY-MM-DD");
    console.log(fdate);
    var puser;
    let ftime = moment(time, "h:mm A").format("H:mm");
    connection();
    con.query("select username from party where name=?",[hall],function(err,row,fields){
        if(err) throw err;
        if(!row.length) {
            res.end(JSON.stringify({success:false, message:"Party hall does not exist"}));
            return;
        }
        else {
            puser = row[0].username;
            con.query("select * from p_reserve where username=? and puser=? and d=? and t=?",[username,puser,fdate,ftime],function(err,row1,fields){
                if(err) throw err;
                if(row1.length) {
                    res.end(JSON.stringify({success:false,message: "Sorry, this slot has been booked already"}));
                    return;
                }
            });
            con.query("insert into p_reserve values(?,?,?,?)",[username,puser,fdate,ftime],function(err2,result){
                if(err2)  {
                    res.end(JSON.stringify({success:false,message: "Please check the date and time entered."}));
                }
                else    
                    res.end(JSON.stringify({success:true,message: "Party hall has been booked successfully!!"}));
            });
        }
    }); 
});

//view notifications
app.post("/api/view_notif",function(req,res){
    let {username} = req.body;
    res.writeHead(200,{"Content-Type":"application/json"});
    connection();
    con.query("select * from notification where username=?",[username],function(err,result,fields){
        if(err) throw err;
        if(!result.length)
            res.end(JSON.stringify({success:false, message:"No notifications yet!!"}));
        else
            res.end(JSON.stringify({success:true, message:result}));
    });
});

//add notifications 
app.post("/api/addNotif",function(req,res){
    let {msg,name} = req.body;
    res.writeHead(200,{"Content-Type":"application/json"});
    connection();
    con.query("select username from user where notify='y'",(err,result,fields)=>{
        if(err) throw err;
        console.log(result);
        var i;
        for(i=0;i<result.length;i++) {
            con.query("insert into notification values(?,?,?)",[result[i].username,name,msg],(err1,notify)=>{
                if(err1) throw err1;
            });
        }
        if(i==result.length)
            res.end(JSON.stringify({success:true,notif:"Notifications sent successfully!"}));  
        else
            res.end(JSON.stringify({success:false,notif:"Sorry couldn't send the notifications."}));  
    });
});

app.listen(8080, (err, res) => {
    open("http://localhost:8080/restaurant.html");
});