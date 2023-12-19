// imports
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()


// config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

// Route Public
app.get('/', (req, res) => {
   res.status(200).json('<h1>Bem vindo a minha Api</h1>')
})

// Private Rote
app.get('/user/:id', checkToken, async (req, res) => {
   const id = req.params.id

   // check id user exists
   const user = await User.findById(id, '-password')

   if (!user) {
      return res.status(404).json({ msg: 'Usuario nao encontrado'})
   }

   res.status(200).json({ user })
})

function checkToken(req, res, next) {
   const authHeader = req.headers['authorization']
   const token = authHeader && authHeader.split(" ")[1]

   if (!token) {
      return res.status(401).json({ msg: "Acesso negado!"})
   }

   try {
      const secret = process.env.SECRET
      jwt.verify(token, secret)
      next()
   } catch (error) {
      res.status(400).json({msg: "Token invalido"})
   }
}

// Register User
app.post('/auth/register', async (req, res) => {
   const { name, email, password, confirmpassword} = req.body

   if(!name){
      return res.status(422).json({ msg: 'O nome e obrigatorio!'})
   }
   if(!email){
      return res.status(422).json({ msg: 'O email e obrigatorio!'})
   }
   if(!password){
      return res.status(422).json({ msg: 'A senha e obrigatorio!'})
   }

   if (password !== confirmpassword) {
      return res.status(422).json({ msg: 'as senhas nao conferem!'})
   }

   // check if user exists
   const userExists = await User.findOne({ email: email})

   if (userExists) {
      return res.status(422).json({ msg: 'Por favor, utilize outro e-mail!'})
   }

   // create password
   const salt = await bcrypt.genSalt(12)
   const passwordHash = await bcrypt.hash(password, salt)

   // create user
   const user = new User({
      name,
      email,
      password: passwordHash,
   })

   try {
      await user.save()
      res.status(201).json({ msg: 'Usuario criado com sucesso'})
   } catch (error) {
      console.log(error)
      res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente'})
   }

})

// Login User
app.post('/auth/login', async (req, res) => {
   const {email, password} = req.body

   if(!email){
      return res.status(422).json({ msg: 'O email e obrigatorio!'})
   }
   if(!password){
      return res.status(422).json({ msg: 'A senha e obrigatorio!'})
   }

   // check if user exists
   const user = await User.findOne({ email: email})

   if (!user) {
      return res.status(404).json({ msg: 'Usuario nao encontrado'})
   }

   // check if password match
   const checkPassword = await bcrypt.compare(password, user.password)

   if(!checkPassword) {
      return res.status(422).json({ msg: 'Senha Invalida'})
   }

   try {
      const secret = process.env.SECRET

      const token = jwt.sign(
         {
            id: user._id
         }, secret,
      )

      res.status(201).json({ msg: 'Autenticacao realizada com sucesso ', token})

   } catch(error) {
      console.log(error)

      return res.status(500).json({ 
         msg: 'Aconteceu um erro no servidor, tente novamente mais tarde'
      })
   }
})

// Credenciais
const dbuser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbuser}:${dbPassword}@cursonodejsdicasparadev.xinn6tk.mongodb.net/?retryWrites=true&w=majority`)
   .then(() => {
      app.listen(3000)
      console.log('Conectou ao Banco de Dados')})
   .catch((err) => { console.log(err)
})



