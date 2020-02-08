
const AuthService = require('../Auth/authService')


    function requireAuth(req, res, next) {
        const authToken = req.get('Authorization') || ''
      
        let bearerToken
        if (!authToken.toLowerCase().startsWith('bearer ')) {
          return res.status(401).json({ error: 'Missing bearer token' })
        } else {
          bearerToken = authToken.slice('bearer '.length, authToken.length)
        }
      
        const [tokenUserName, tokenPassword] = AuthService.parseBasicToken(bearerToken)
      
        if (!tokenUserName || !tokenPassword) {
          return res.status(401).json({ error: 'Unauthorized request1' })
        }
      
        AuthService.getUserWithUserName(
          req.app.get('db'),
          tokenUserName
        )
          .then(user => {
              console.log(user.password + ':' + tokenPassword)
              return AuthService.comparePasswords(tokenPassword, user.password)
              .then(passwordsMatch => {
                if(!passwordsMatch) {
                  return res.status(401).json({error : 'Unauthorized request'})
                }
                req.user = user
                next()
              })
          })
          .catch(next)
      }
      
      module.exports = {
        requireAuth,
      }