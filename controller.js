import bcrypt from 'bcrypt';
import { createHash } from 'crypto';
import { validationResult, matchedData } from 'express-validator';
import { generateToken, verifyToken } from './tokenHandler.js';
import DB from './dbConnection.js';

const validation_result = validationResult.withDefaults({
    formatter: (error) => error.msg,
});

export const validate = (req, res, next) => {
    const errors = validation_result(req).mapped();
    if (Object.keys(errors).length) {
        return res.status(422).json({
            status: 422,
            errors,
        });
    }
    next();
};

// If email already exists in database
export const fetchUserByEmailOrID = async (data, isEmail = true) => {
    let sql = 'SELECT * FROM `users` WHERE `email`=?';
    if (!isEmail)
        sql = 'SELECT `id` ,`name`, `email` FROM `users` WHERE `id`=?';
    const [row] = await DB.execute(sql, [data]);
    return row;
};

// controller.js

export default {
    signup: async (req, res, next) => {
        try {
            const {
                name,
                companyname,
                email,
                password,
                role,
                firmname,
                annexname,
                annextype,
            } = matchedData(req);

            const saltRounds = 10;
            const hashPassword = await bcrypt.hash(password, saltRounds);

            // Insert user details into the users table
            const [userResult] = await DB.execute(
                'INSERT INTO `users` (`name`, `email`, `password`, `role`, `firmname`) VALUES (?, ?, ?, ?, ?)',
                [name, email, hashPassword, role, firmname]
            );

            const userId = userResult.insertId;

            // Insert annexname into user_annexname table
            if (annexname && annexname.length > 0) {
                await Promise.all(
                    annexname.map(async (annex) => {
                        await DB.execute(
                            'INSERT INTO `users_annexname` (`user_id`, `annexname`) VALUES (?, ?)',
                            [userId, annex]
                        );
                    })
                );
            }

            // Insert annextype into user_annextype table
            if (annextype && annextype.length > 0) {
                await Promise.all(
                    annextype.map(async (type) => {
                        await DB.execute(
                            'INSERT INTO `users_annextype` (`user_id`, `annextype`) VALUES (?, ?)',
                            [userId, type]
                        );
                    })
                );
            }

            // Insert companyname into user_companyname table
            if (companyname && companyname.length > 0) {
                await Promise.all(
                    companyname.map(async (company) => {
                        await DB.execute(
                            'INSERT INTO `users_companyname` (`user_id`, `companyname`) VALUES (?, ?)',
                            [userId, company]
                        );
                    })
                );
            }

            res.status(201).json({
                status: 201,
                message: 'You have been successfully registered.',
                user_id: userId,
            });
        } catch (err) {
            next(err);
        }
    },


    

    login: async (req, res, next) => {
        try {
            const { user, password } = req.body;
            const verifyPassword = await bcrypt.compare(
                password,
                user.password
            );
            if (!verifyPassword) {
                return res.status(422).json({
                    status: 422,
                    message: 'Incorrect password!',
                });
            }

            // Generating Access and Refresh Token
            const access_token = generateToken({ id: user.id });
            const refresh_token = generateToken({ id: user.id }, false);

            const md5Refresh = createHash('md5')
                .update(refresh_token)
                .digest('hex');

            // Storing refresh token in MD5 format
            const [result] = await DB.execute(
                'INSERT INTO `refresh_tokens` (`user_id`,`token`) VALUES (?,?)',
                [user.id, md5Refresh]
            );

            if (!result.affectedRows) {
                throw new Error('Failed to whitelist the refresh token.');
            }
            res.json({
                status: 200,
                access_token,
                refresh_token,
            });
        } catch (err) {
            next(err);
        }
    },

    getUser: async (req, res, next) => {
        try {
            // Verify the access token
            const data = verifyToken(req.headers.access_token);
            if (data?.status) return res.status(data.status).json(data);
            // fetching user by the `id` (column)
            const user = await fetchUserByEmailOrID(data.id, false);
            if (user.length !== 1) {
                return res.status(404).json({
                    status: 404,
                    message: 'User not found',
                });
            }
            res.json({
                status: 200,
                user: user[0],
            });
        } catch (err) {
            next(err);
        }
    },

    refreshToken: async (req, res, next) => {
        try {
            const refreshToken = req.headers.refresh_token;
            // Verify the refresh token
            const data = verifyToken(refreshToken, false);
            if (data?.status) return res.status(data.status).json(data);

            // Converting refresh token to md5 format
            const md5Refresh = createHash('md5')
                .update(refreshToken)
                .digest('hex');

            // Finding the refresh token in the database
            const [refTokenRow] = await DB.execute(
                'SELECT * from `refresh_tokens` WHERE token=?',
                [md5Refresh]
            );

            if (refTokenRow.length !== 1) {
                return res.json({
                    status: 401,
                    message: 'Unauthorized: Invalid Refresh Token.',
                });
            }

            // Generating new access and refresh token
            const access_token = generateToken({ id: data.id });
            const refresh_token = generateToken({ id: data.id }, false);

            const newMd5Refresh = createHash('md5')
                .update(refresh_token)
                .digest('hex');

            // Replacing the old refresh token to new refresh token
            const [result] = await DB.execute(
                'UPDATE `refresh_tokens` SET `token`=? WHERE `token`=?',
                [newMd5Refresh, md5Refresh]
            );

            if (!result.affectedRows) {
                throw new Error('Failed to whitelist the Refresh token.');
            }

            res.json({
                status: 200,
                access_token,
                refresh_token,
            });
        } catch (err) {
            next(err);
        }
    },






    ///////////////////  Extra Code : 

    /*getAllUsers: async (req, res, next) => {
        try {
            // Fetch all users from the database
            const [users] = await DB.execute('SELECT * FROM `users`');
            res.json({
                users: Array.isArray(users) ? users : [users],
            });
        } catch (err) {
            next(err);
        }
    },*/
    /*getAllUsers: async (req, res, next) => {
        try {
            // Fetch all users along with their associated data from the database
            const query = `
            SELECT
            u.*,
            CONCAT('[', GROUP_CONCAT(DISTINCT JSON_OBJECT('annextype', ua.annextype)), ']') AS annextypes,
            CONCAT('[', GROUP_CONCAT(DISTINCT JSON_OBJECT('annexname', un.annexname)), ']') AS annexnames,
            CONCAT('[', GROUP_CONCAT(DISTINCT JSON_OBJECT('companyname', uc.companyname)), ']') AS companynames
        FROM
            users u
            LEFT JOIN users_annextype ua ON u.id = ua.user_id
            LEFT JOIN users_annexname un ON u.id = un.user_id
            LEFT JOIN users_companyname uc ON u.id = uc.user_id
        GROUP BY
            u.id;        
        
        `;
            
    
            const [users] = await DB.execute(query);
    
            res.json({
                users: Array.isArray(users) ? users : [users],
            });
        } catch (err) {
            next(err);
        }
    },*/

    getAllUsers: async (req, res, next) => {
        try {
            // Fetch all users along with their associated data from the database
            const query = `
                SELECT
                    u.*,
                    CONCAT('[', GROUP_CONCAT(DISTINCT '"', ua.annextype, '"' SEPARATOR ','), ']') AS annextype,
                    CONCAT('[', GROUP_CONCAT(DISTINCT '"', un.annexname, '"' SEPARATOR ','), ']') AS annexname,
                    CONCAT('[', GROUP_CONCAT(DISTINCT '"', uc.companyname, '"' SEPARATOR ','), ']') AS companyname
                FROM
                    users u
                    LEFT JOIN users_annextype ua ON u.id = ua.user_id
                    LEFT JOIN users_annexname un ON u.id = un.user_id
                    LEFT JOIN users_companyname uc ON u.id = uc.user_id
                GROUP BY
                    u.id;
            `;
    
            const [users] = await DB.execute(query);
    
            // Transform the results to the desired JSON structure
            const transformedUsers = users.map(user => ({
                id: user.id,
                name: user.name,
                email: user.email,
                password: user.password,
                created_at: user.created_at,
                updated_at: user.updated_at,
                role: user.role,
                firmname: user.firmname,
                annextype: JSON.parse(user.annextype),
                annexname: JSON.parse(user.annexname),
                companyname: JSON.parse(user.companyname),
            }));
    
            res.json({
                users: transformedUsers,
            });
        } catch (err) {
            next(err);
        }
    },
    
    
    

    

    getUsersByCompany: async (req, res, next) => {
        try {
            const { companyname} = req.query;

            // Fetch users by company name from the database
            const [users] = await DB.execute(
                'SELECT * FROM `users` WHERE `companyname`=?',
                [companyname]
            );

            if (users.length === 0) {
                return res.status(404).json({
                    status: 404,
                    message: 'Users not found for the specified company.',
                });
            }

            res.json({
                status: 200,
                users,
            });
        } catch (err) {
            next(err);
        }
    },
};