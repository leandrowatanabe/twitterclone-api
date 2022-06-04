import Koa from 'koa'
import bodyParser from 'koa-bodyparser'
import { router } from './routes.js'
import cors from '@koa/cors'

export const app = new Koa()

app.use(cors())
app.use(bodyParser())
app.use(router.routes())
app.use(router.allowedMethods())