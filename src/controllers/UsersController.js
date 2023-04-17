const { hash, compare }  = require('bcryptjs')

const AppError = require('../utils/AppError')

const sqliteConnection = require('../database/sqlite')

class UsersController {
    async create(request, response) {
        const { name, email, password } = request.body

        const database = await sqliteConnection()
        const checkUserExists = await database.get('Select * from users where email = (?)', [email])
        
        if(checkUserExists) {
            throw new AppError('Email já cadastrado.')
        }

        const hashedPassword = await hash(password, 8)

        await database.run('insert into users (name, email, password) values (?, ?, ?)', [name, email, hashedPassword])

        return response.json()
    }

    async update(request, response) {
        const { name, email, password, old_password } = request.body
        const { id } = request.params

        const database = await sqliteConnection()
        const user = await database.get('Select * from users where id = (?)', [id])
        
        if(!user) {
            throw new AppError('Usuário não encontrado.')
        }

        const userWithEmailUpdated = await database.get('Select * from users where email = (?)', [email])

        if(userWithEmailUpdated && userWithEmailUpdated.id !== user.id) {
            throw new AppError('Este email já está em uso.')
        }
        
        user.name = name ?? user.name
        user.email = email ?? user.email

        if(password && !old_password) {
            throw new AppError('Você precisa informar a senha antiga.')
        }

        if(password && old_password) {
            const checkOldPassword = await compare(old_password, user.password)

            if(!checkOldPassword) {
                throw new AppError('A senha antiga não confere.')
            }

            user.password = await hash(password, 8)
        }

        await database.run(`Update users set
        name = ?,
        email = ?,
        password = ?,
        updated_at = Datetime('now')
        where id = ?
        `, [user.name, user.email, user.password, id])

        return response.json()
    }
}

module.exports = UsersController