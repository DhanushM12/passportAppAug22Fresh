const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt')

function initialize(passport, getUserByEmail, getUserByID){
    const authenticator = async (email, password, done) => {
            const user = getUserByEmail(email)
            if(!user){
                return done(null, false); // email id doesn't exits
            }
            try {
                if(await bcrypt.compare(password, user.password)){
                    return done(null, user); // user is valid and can successfully logged in
                }
                else{
                    return done(null, false); // password is incorrect
                }
            } catch (error) {
                return done(error);
            }
    }
    passport.use(new LocalStrategy({usernameField: 'email'}, authenticator));
    passport.serializeUser(function(user, done) {
        done(null, user.id);
      });
      
      passport.deserializeUser(function(id, done) {
          done(null, getUserByID(id));
      });
}


module.exports = initialize;