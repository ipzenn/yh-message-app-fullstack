const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')
const bodyParser = require('body-parser')

const PORT = process.env.PORT || '3000'
const app = express()
app.use(cors())
app.use(bodyParser.json())

const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/messages"
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: true })
mongoose.Promise = Promise
mongoose.set('useFindAndModify', false)

mongoose.connection.once("open", () => {
  console.log("Connected to mongodb")
})

mongoose.connection.on("error", err => {
  console.error("connection error:", err)
})

const listEndpoints = require('express-list-endpoints');

const Message = mongoose.model('Message', {
  message: {
    type: String,
    required: true,
    minlength: 5,
    maxlength: 140
  },
  hearts: {
    type: Number,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
})

app.get('/', async (req, res) => {
  res.send(listEndpoints(app))
})

app.get('/messages', async (req, res) => {
  const messages = await Message.find().sort({ createdAt: 'desc' }).limit(20).exec()
  res.json(messages)
})

app.post('/messages', async (req, res) => {
  const message = new Message({ message: req.body.message, hearts: 0 })

  try {
    const saved = await message.save()
    res.status(201).json(saved)
  } catch (err) {
    res.status(400).json({ message: 'Could not save message', errors: err.errors })
  }
})

app.post('/messages/:id/like', async (req, res) => {
  try {
    const message = await Message.findOneAndUpdate({ _id: req.params.id }, { $inc: { hearts: 1 } }, { new: true })
    res.json(message)
  } catch (err) {
    res.status(400).json({ message: 'Could not save heart', errors: err.errors })
  }
})

app.patch('/messages/:id', async (req, res) => {
  try {
    const message = await Message.findByIdAndUpdate(req.params.id, { message: req.body.message }, { new: true, runValidators: true })
    if (!message) {
      return res.status(404).json({ message: 'Message not found' })
    }
    res.json(message)
  } catch (err) {
    res.status(400).json({ message: 'Could not update message', errors: err.errors })
  }
})

app.delete('/messages/:id', async (req, res) => {
  try {
    const message = await Message.findByIdAndDelete(req.params.id)
    if (!message) {
      return res.status(404).json({ message: 'Message not found' })
    }
    res.json({ message: 'Message deleted successfully' })
  } catch (err) {
    res.status(400).json({ message: 'Could not delete message', errors: err.errors })
  }
})

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`)
})