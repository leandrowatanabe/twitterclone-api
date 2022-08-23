import Router from '@koa/router'
import { PrismaClient } from '@prisma/client'
import { hashSync, compareSync } from 'bcrypt'
import jwt from 'jsonwebtoken'

export const router = new Router()

const prisma = new PrismaClient()

router.get('/tweets', async ctx => {
    const [, token] = ctx.request.headers?.authorization?.split(' ') || []

    if (!token) {
        ctx.status = 401
        return
    }

    try {
        jwt.verify(token, process.env.JWT_SECRET)
        const tweets = await prisma.tweet.findMany({
            include: {
                user: true
            },
            orderBy:[
                {
                    timestamp: 'desc'
                }
            ]
        })
        ctx.body = tweets
    } catch (error) {
        console.error
        if (typeof error === 'JsonWebTokenError') {
            ctx.status = 401
            return
        }

        ctx.status = 500
        return
    }
})

router.post('/tweets', async ctx=>{
    const [, token] = ctx.request.headers?.authorization?.split(' ') || []

    if(!token){
        ctx.status = 401
        return
    }
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET)

        const tweet = await prisma.tweet.create({
            data: {
                userId:     payload.sub,
                text:       ctx.request.body.text,
                timestamp:  ctx.request.body.timestamp
            }
        })

        ctx.body = tweet
 
    } catch(error){
        
        console.error(error)
        ctx.status = 401
        return
    }
})

router.get('/users', async ctx=>{
    const [, token] = ctx.request.headers?.authorization?.split(' ') || []

    if(!token){
        ctx.status = 401
        return
    }
    try {
       
        const users = await prisma.user.findMany({
            select:{
                id:     true,
                name:       true,
                username:   true,
                tweets: true
            }
        })

        ctx.body = users
 
    } catch(error){
        console.error(error)
        ctx.status = 401
        return
    }
})

router.post('/signup', async ctx => {
    const saltRounts = 10
    const password = hashSync(ctx.request.body.password, saltRounts)

    try{
        const user = await prisma.user.create({
            data:{
                name:       ctx.request.body.name,
                username:   ctx.request.body.username,
                email:      ctx.request.body.email,
                password,
            }
        })

        const accessToken = jwt.sign({
            sub: user.id
        }, process.env.JWT_SECRET,{ expiresIn: '12h'})
        
        ctx.body = {
            id:         user.id,
            name:       user.name,
            username:   user.username,
            email:      user.email,
            accessToken
        }
    } catch(error){
        console.error(error)
        if(error.meta && !error.meta.target){
            ctx.status = 422
            ctx.body = "Email ou nome de usuario já existe"
            return
        }

        ctx.status = 500
        ctx.body = 'Internal error'
    }
})

router.get('/login', async ctx => {
    const [, token] = ctx.request.headers.authorization.split(' ')
    const [email, plainTextPassword] = Buffer.from(token, 'base64').toString().split(':')

    const user = await prisma.user.findUnique({
        where: { email }
    })

    if (!user){
        ctx.body = 404
    
        return
    } 

    const passwordMatch = compareSync(plainTextPassword, user.password)

    if(passwordMatch){
        const accessToken = jwt.sign({
            sub: user.id
        }, process.env.JWT_SECRET,{ expiresIn: '12h'})

        ctx.body = {
            id:             user.id,
            name:           user.name,
            username:       user.username,
            email:          user.email,
            accessToken,
        }

        return
    }


    ctx.status = 404
}) 