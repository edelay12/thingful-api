const AuthService = require('../Auth/authService')


    function requireAuth(req, res, next) {
        const authToken = req.get('Authorization') || ''
      
        let basicToken
        if (!authToken.toLowerCase().startsWith('basic ')) {
          return res.status(401).json({ error: 'Missing basic token' })
        } else {
          basicToken = authToken.slice('basic '.length, authToken.length)
        }
      
        const [tokenUserName, tokenPassword] = AuthService.parseBasicToken(basicToken)
      
        if (!tokenUserName || !tokenPassword) {
          return res.status(401).json({ error: 'Unauthorized request1' })
        }
      
        AuthService.getUserWithUserName(
          req.app.get('db'),
          tokenUserName
        )
          .then(user => {
              console.log(user + '-----------tp' + tokenPassword)
            if (!user || user.password !== tokenPassword) {
              return res.status(401).json({ error: 'Unauthorized request2' })
            }
      
            req.user = user
            next()
          })
          .catch(next)
      }
      
      module.exports = {
        requireAuth,
      }