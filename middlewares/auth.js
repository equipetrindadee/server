    import jwt from "jsonwebtoken";
    import {promisify} from 'util'
    import 'dotenv/config'





    async function validarToken(req, res, next) {

        const header = req.headers.authorization
        if (!header) {
            return res.json({
                error: true,
                mensagem: "Token não informado!"
            })
        }

        const [bearer, token] = header.split(' ')
        if (!token) {
            return res.json({
                error: true,
                mensagem: "Precisa realizar o login!"
            })
        }
        try {
            const decod = await promisify(jwt.verify)(token,process.env.SECRET)
            req.userId = decod.id

            return next()

        } catch (error) {
            return res.json({
                error: true,
                mensagem: "Token inválido!"
            })
        }
    }


    export default validarToken