import { Router} from 'express';
import { body, check } from 'express-validator';
import controller, { validate, fetchUserByEmailOrID } from './controller.js';

const routes = Router({ strict: true });

// Token Validation Rule
const tokenValidation = (isRefresh = false) => {
    let refreshText = isRefresh ? 'Refresh' : 'Authorization';

    return [
        check('Authorization', `Please provide your ${refreshText} token`)
            .exists()
            .not()
            .isEmpty()
            .custom((value, { req }) => {
                if (!value.startsWith('Bearer') || !value.split(' ')[1]) {
                    throw new Error(`Invalid ${refreshText} token`);
                }
                if (isRefresh) {
                    req.headers.refresh_token = value.split(' ')[1];
                    return true;
                }
                req.headers.access_token = value.split(' ')[1];
                return true;
            }),
    ];
};

// Register a new User
routes.post(
    '/signup',
    [
        body('name')
            .trim()
            .not()
            .isEmpty()
            .withMessage('Name must not be empty.')
            .isLength({ min: 3 })
            .withMessage('Name must be at least 3 characters long')
            .escape(),
        body('email', 'Invalid email address.')
            .trim()
            .isEmail()
            .custom(async (email) => {
                const isExist = await fetchUserByEmailOrID(email);
                if (isExist.length)
                    throw new Error(
                        'A user already exists with this e-mail address'
                    );
                return true;
            }),
        body('password')
            .trim()
            .isLength({ min: 6 })
            .withMessage('Password must be at least 4 characters long'),
        body('role')
            .trim()
            .not()
            .isEmpty()
            .withMessage('Role must not be empty.')
            .escape(),
        body('firmname')
            .trim()
            .not()
            .isEmpty()
            .escape(),
        body('annexname')
            .optional({ nullable: true, checkFalsy: true })
            .isArray()
            .withMessage('Annex name must be an array of strings.')
            .custom((value) => {
                if (value && !value.every((item) => typeof item === 'string')) {
                    throw new Error('Annex name must be an array of strings.');
                }
                return true;
            }),
        body('annextype')
            .optional({ nullable: true, checkFalsy: true })
            .isArray()
            .withMessage('Annex type must be an array of strings.')
            .custom((value) => {
                if (value && !value.every((item) => typeof item === 'string')) {
                    throw new Error('Annex type must be an array of strings.');
                }
                return true;
            }),
        body('companyname')
            .optional({ nullable: true, checkFalsy: true })
            .isArray()
            .withMessage('Company name must be an array of strings.')
            .custom((value) => {
                if (value && !value.every((item) => typeof item === 'string')) {
                    throw new Error('Company name must be an array of strings.');
                }
                return true;
            }),
    ],
    validate,
    controller.signup
);

// Login user through email and password
routes.post(
    '/login',
    [
        body('email', 'Invalid email address.')
            .trim()
            .isEmail()
            .custom(async (email, { req }) => {
                const isExist = await fetchUserByEmailOrID(email);
                if (isExist.length === 0)
                    throw new Error('Your email is not registered.');
                req.body.user = isExist[0];
                return true;
            }),
        body('password', 'Incorrect Password').trim().isLength({ min: 4 }),
    ],
    validate,
    controller.login
);

// Get the user data by providing the access token
routes.get('/profile', tokenValidation(), validate, controller.getUser);

// Get new access and refresh token by providing the refresh token
routes.get(
    '/refresh',
    tokenValidation(true),
    validate,
    controller.refreshToken
);


// Get all users
routes.get('/getallusers', controller.getAllUsers);

/*routes.get('/getallusers', async (req, res, next) => {
    try {
        // Fetch all users along with their associated data from the database
        const query = `
            SELECT
                u.*,
                GROUP_CONCAT(DISTINCT ua.annextype) AS annextype,
                GROUP_CONCAT(DISTINCT un.annexname) AS annexname,
                GROUP_CONCAT(DISTINCT uc.companyname) AS companyname
            FROM
                users u
                LEFT JOIN users_annextype ua ON u.id = ua.user_id
                LEFT JOIN users_annexname un ON u.id = un.user_id
                LEFT JOIN users_companyname uc ON u.id = uc.user_id
            GROUP BY
                u.id
        `;

        const [result] = await DB.execute(query);
        res.json({
            users: Array.isArray(result) ? result : [result],
        });
    } catch (err) {
        next(err);
    }
});*/

// Get users by company name and company id
routes.get(
    '/getusersbycompanyname',
    [
        check('companyname').trim().not().isEmpty().escape(),
    ],
    tokenValidation(),
    validate,
    controller.getUsersByCompany
);


export default routes;
