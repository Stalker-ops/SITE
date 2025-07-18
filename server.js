const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

// Настройка загрузки файлов
const upload = multer({
    dest: 'uploads/',
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Security Middleware
app.use(helmet());
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
});
app.use(limiter);

// Standard Middleware
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));
app.use(bodyParser.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname)));

// Session configuration
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        concurrentDB: true
    }),
    genid: () => uuidv4(),
    secret: process.env.SESSION_SECRET || 'your-secret-key-here',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production'
    }
}));

// Database setup
const db = new sqlite3.Database('./database.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
        process.exit(1);
    }
    console.log('Connected to the SQLite database.');
    initializeDatabase();
});

// Database initialization
function initializeDatabase() {
    db.serialize(() => {
        // Users table with improved schema
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            birthday TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            status TEXT DEFAULT 'online',
            tag TEXT DEFAULT '0000',
            bio TEXT DEFAULT '',
            country TEXT DEFAULT '',
            avatar_url TEXT DEFAULT '',
            profile_banner TEXT DEFAULT '',
            custom_status TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            email_verified BOOLEAN DEFAULT 0,
            verification_token TEXT,
            reset_token TEXT,
            reset_token_expires TIMESTAMP
        )`);

        // Badges table
        db.run(`CREATE TABLE IF NOT EXISTS badges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            icon TEXT NOT NULL,
            color TEXT DEFAULT '#5865F2',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )`);

        // Improved friends table with status tracking
        db.run(`CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending', -- 'pending', 'accepted', 'blocked'
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(friend_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, friend_id)
        )`);

        // Activities table
        db.run(`CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            details TEXT,
            icon TEXT DEFAULT 'fa-gamepad',
            color TEXT DEFAULT '#5865F2',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )`);
    });
}

// Middleware для проверки авторизации
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Требуется авторизация' });
    }
    next();
}

// Middleware для логирования запросов
function requestLogger(req, res, next) {
    console.log(`${req.method} ${req.originalUrl}`);
    next();
}

app.use(requestLogger);

// ==================== АУТЕНТИФИКАЦИЯ ====================

// Регистрация пользователя
app.post('/register', async (req, res) => {
    try {
        const { email, username, password, birthday } = req.body;

        // Валидация входных данных
        if (!email || !username || !password || !birthday) {
            return res.status(400).json({ success: false, message: 'Все поля обязательны для заполнения' });
        }

        if (password.length < 8) {
            return res.status(400).json({ success: false, message: 'Пароль должен содержать минимум 8 символов' });
        }

        // Проверка существования пользователя
        db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username], async (err, row) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'Ошибка сервера' });
            }

            if (row) {
                const message = row.email === email 
                    ? 'Пользователь с такой почтой уже существует' 
                    : 'Пользователь с таким именем уже существует';
                return res.status(409).json({ success: false, message });
            }

            // Хеширование пароля
            const hash = await bcrypt.hash(password, saltRounds);

            // Создание пользователя
            db.run(
                'INSERT INTO users (email, username, password_hash, birthday) VALUES (?, ?, ?, ?)',
                [email, username, hash, birthday],
                function(err) {
                    if (err) {
                        console.error('Database error:', err);
                        return res.status(500).json({ success: false, message: 'Ошибка при регистрации' });
                    }

                    // Установка сессии
                    req.session.userId = this.lastID;
                    
                    res.json({ 
                        success: true, 
                        message: 'Регистрация успешна!',
                        redirectTo: '/client'
                    });
                }
            );
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// Вход пользователя
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email и пароль обязательны' });
    }

    db.get('SELECT id, password_hash, is_active FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Ошибка сервера' });
        }

        if (!user) {
            return res.status(401).json({ success: false, message: 'Неверный email или пароль' });
        }

        if (!user.is_active) {
            return res.status(403).json({ success: false, message: 'Аккаунт заблокирован' });
        }

        // Проверка пароля
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ success: false, message: 'Неверный email или пароль' });
        }

        // Обновление времени последнего входа
        db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

        // Установка сессии
        req.session.userId = user.id;
        
        res.json({ 
            success: true, 
            message: 'Авторизация успешна!',
            redirectTo: '/client'
        });
    });
});

// Выход пользователя
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ success: false, message: 'Ошибка при выходе' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true, message: 'Вы успешно вышли', redirectTo: '/login' });
    });
});

// ==================== ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ ====================

// Получение информации о текущем пользователе
app.get('/api/user/me', requireAuth, (req, res) => {
    getUserProfile(req.session.userId)
        .then(profile => {
            res.json({
                success: true,
                profile
            });
        })
        .catch(error => {
            console.error('Error fetching user profile:', error);
            res.status(500).json({ success: false, message: 'Ошибка при получении профиля' });
        });
});

// Получение информации о другом пользователе
app.get('/api/user/:id', requireAuth, (req, res) => {
    const userId = req.params.id;

    // Проверка, является ли пользователь другом
    db.get(
        `SELECT status FROM friends 
        WHERE (user_id = ? AND friend_id = ? AND status = 'accepted')
        OR (user_id = ? AND friend_id = ? AND status = 'accepted')`,
        [req.session.userId, userId, userId, req.session.userId],
        (err, friendship) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'Ошибка сервера' });
            }

            const isFriend = !!friendship;

            getUserProfile(userId, isFriend)
                .then(profile => {
                    res.json({
                        success: true,
                        profile,
                        isFriend
                    });
                })
                .catch(error => {
                    console.error('Error fetching user profile:', error);
                    if (error.message === 'User not found') {
                        return res.status(404).json({ success: false, message: 'Пользователь не найден' });
                    }
                    res.status(500).json({ success: false, message: 'Ошибка при получении профиля' });
                });
        }
    );
});

// Функция для получения профиля пользователя
function getUserProfile(userId, includePrivateData = true) {
    return new Promise((resolve, reject) => {
        db.get(
            `SELECT 
                id, username, email, status, tag, bio, country,
                avatar_url, profile_banner, custom_status,
                strftime('%d.%m.%Y', created_at) as created_at,
                strftime('%d.%m.%Y', last_login) as last_login
            FROM users 
            WHERE id = ?`,
            [userId],
            (err, user) => {
                if (err) {
                    return reject(err);
                }

                if (!user) {
                    return reject(new Error('User not found'));
                }

                // Получаем бейджи пользователя
                db.all(
                    'SELECT name, icon, color FROM badges WHERE user_id = ?',
                    [userId],
                    (err, badges) => {
                        if (err) {
                            return reject(err);
                        }

                        // Получаем активность пользователя
                        db.get(
                            'SELECT name, details, icon, color FROM activities WHERE user_id = ?',
                            [userId],
                            (err, activity) => {
                                if (err) {
                                    return reject(err);
                                }

                                const profile = {
                                    id: user.id,
                                    username: user.username,
                                    tag: user.tag,
                                    status: user.status || 'online',
                                    avatar: user.avatar_url || `https://i.pravatar.cc/150?u=${user.id}`,
                                    banner: user.profile_banner,
                                    created_at: user.created_at,
                                    last_login: user.last_login,
                                    badges: badges || [],
                                    activity: activity || null
                                };

                                if (includePrivateData) {
                                    profile.bio = user.bio;
                                    profile.country = user.country;
                                    profile.custom_status = user.custom_status ? JSON.parse(user.custom_status) : null;
                                }

                                resolve(profile);
                            }
                        );
                    }
                );
            }
        );
    });
}

// Обновление профиля
app.put('/api/user/profile', requireAuth, (req, res) => {
    const { username, bio, status, custom_status, country } = req.body;
    
    // Валидация данных
    if (username && username.length < 3) {
        return res.status(400).json({ success: false, message: 'Имя пользователя должно содержать минимум 3 символа' });
    }

    if (bio && bio.length > 500) {
        return res.status(400).json({ success: false, message: 'Биография не должна превышать 500 символов' });
    }

    const updates = {};
    const params = [];

    if (username) {
        updates.username = username;
        params.push(username);
    }
    if (bio) {
        updates.bio = bio;
        params.push(bio);
    }
    if (status) {
        updates.status = status;
        params.push(status);
    }
    if (custom_status) {
        updates.custom_status = JSON.stringify(custom_status);
        params.push(updates.custom_status);
    }
    if (country) {
        updates.country = country;
        params.push(country);
    }

    if (Object.keys(updates).length === 0) {
        return res.status(400).json({ success: false, message: 'Нет данных для обновления' });
    }

    const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    params.push(req.session.userId);

    db.run(
        `UPDATE users SET ${setClause} WHERE id = ?`,
        params,
        function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'Ошибка при обновлении профиля' });
            }
            
            res.json({ success: true, message: 'Профиль успешно обновлен' });
        }
    );
});

// Загрузка аватарки
app.post('/api/user/avatar', requireAuth, upload.single('avatar'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'Файл не загружен' });
    }

    // Здесь должна быть логика сохранения файла (например, загрузка в облачное хранилище)
    // Для примера просто сохраняем путь к файлу
    const avatarPath = `/uploads/avatars/${req.session.userId}_${Date.now()}${path.extname(req.file.originalname)}`;

    // Обновляем аватар в базе данных
    db.run(
        'UPDATE users SET avatar_url = ? WHERE id = ?',
        [avatarPath, req.session.userId],
        function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'Ошибка при обновлении аватара' });
            }

            // Удаляем временный файл
            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting temp file:', err);
            });

            res.json({ 
                success: true, 
                message: 'Аватар успешно обновлен',
                avatarUrl: avatarPath
            });
        }
    );
});

// Загрузка баннера профиля
app.post('/api/user/banner', requireAuth, upload.single('banner'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'Файл не загружен' });
    }

    const bannerPath = `/uploads/banners/${req.session.userId}_${Date.now()}${path.extname(req.file.originalname)}`;

    db.run(
        'UPDATE users SET profile_banner = ? WHERE id = ?',
        [bannerPath, req.session.userId],
        function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'Ошибка при обновлении баннера' });
            }

            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting temp file:', err);
            });

            res.json({ 
                success: true, 
                message: 'Баннер успешно обновлен',
                bannerUrl: bannerPath
            });
        }
    );
});

// ==================== СИСТЕМА ДРУЗЕЙ ====================

// Добавление/удаление друга
app.post('/api/user/friends', requireAuth, (req, res) => {
    const { userId, action } = req.body;
    
    if (!['add', 'remove', 'block', 'unblock'].includes(action)) {
        return res.status(400).json({ success: false, message: 'Некорректное действие' });
    }
    
    if (parseInt(userId) === req.session.userId) {
        return res.status(400).json({ success: false, message: 'Нельзя добавить самого себя' });
    }
    
    if (action === 'add') {
        // Проверяем, не заблокирован ли пользователь
        db.get(
            `SELECT status FROM friends 
            WHERE (user_id = ? AND friend_id = ? AND status = 'blocked')
            OR (user_id = ? AND friend_id = ? AND status = 'blocked')`,
            [req.session.userId, userId, userId, req.session.userId],
            (err, row) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
                }

                if (row) {
                    return res.status(403).json({ 
                        success: false, 
                        message: row.user_id === req.session.userId 
                            ? 'Вы заблокировали этого пользователя' 
                            : 'Этот пользователь заблокировал вас' 
                    });
                }

                // Добавляем запрос в друзья
                db.run(
                    `INSERT OR REPLACE INTO friends (user_id, friend_id, status) 
                    VALUES (?, ?, 
                        CASE 
                            WHEN EXISTS (
                                SELECT 1 FROM friends 
                                WHERE user_id = ? AND friend_id = ? AND status = 'pending'
                            ) THEN 'accepted'
                            ELSE 'pending'
                        END
                    )`,
                    [req.session.userId, userId, userId, req.session.userId],
                    function(err) {
                        if (err) {
                            console.error('Database error:', err);
                            return res.status(500).json({ success: false, message: 'Ошибка сервера' });
                        }
                        
                        const message = this.changes > 0 
                            ? 'Запрос на дружбу отправлен' 
                            : 'Запрос на дружбу уже существует';
                        
                        res.json({ 
                            success: true, 
                            message
                        });
                    }
                );
            }
        );
    } else if (action === 'remove') {
        db.run(
            `DELETE FROM friends 
            WHERE (user_id = ? AND friend_id = ?)
            OR (user_id = ? AND friend_id = ?)`,
            [req.session.userId, userId, userId, req.session.userId],
            function(err) {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
                }
                
                res.json({ 
                    success: true, 
                    message: 'Пользователь удален из друзей'
                });
            }
        );
    } else if (action === 'block') {
        db.run(
            `INSERT OR REPLACE INTO friends (user_id, friend_id, status) 
            VALUES (?, ?, 'blocked')`,
            [req.session.userId, userId],
            function(err) {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
                }
                
                res.json({ 
                    success: true, 
                    message: 'Пользователь заблокирован'
                });
            }
        );
    } else if (action === 'unblock') {
        db.run(
            `DELETE FROM friends 
            WHERE user_id = ? AND friend_id = ? AND status = 'blocked'`,
            [req.session.userId, userId],
            function(err) {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ success: false, message: 'Ошибка сервера' });
                }
                
                res.json({ 
                    success: true, 
                    message: 'Пользователь разблокирован'
                });
            }
        );
    }
});

// Получение списка друзей
app.get('/api/user/friends', requireAuth, (req, res) => {
    db.all(
        `SELECT 
            u.id, u.username, u.tag, u.status, 
            u.avatar_url, u.bio, u.custom_status,
            f.status as friendship_status
        FROM friends f
        JOIN users u ON u.id = f.friend_id
        WHERE f.user_id = ? AND f.status = 'accepted'`,
        [req.session.userId],
        (err, friends) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'Ошибка сервера' });
            }
            
            const formattedFriends = friends.map(friend => ({
                id: friend.id,
                username: friend.username,
                tag: friend.tag,
                status: friend.status,
                avatar: friend.avatar_url || `https://i.pravatar.cc/150?u=${friend.id}`,
                custom_status: friend.custom_status ? JSON.parse(friend.custom_status) : null,
                bio: friend.bio,
                friendship_status: friend.friendship_status
            }));
            
            res.json({ success: true, friends: formattedFriends });
        }
    );
});

// Получение списка входящих заявок в друзья
app.get('/api/user/friends/requests', requireAuth, (req, res) => {
    db.all(
        `SELECT 
            u.id, u.username, u.tag, u.status, 
            u.avatar_url, u.created_at
        FROM friends f
        JOIN users u ON u.id = f.user_id
        WHERE f.friend_id = ? AND f.status = 'pending'`,
        [req.session.userId],
        (err, requests) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, message: 'Ошибка сервера' });
            }
            
            const formattedRequests = requests.map(request => ({
                id: request.id,
                username: request.username,
                tag: request.tag,
                status: request.status,
                avatar: request.avatar_url || `https://i.pravatar.cc/150?u=${request.id}`,
                created_at: request.created_at
            }));
            
            res.json({ success: true, requests: formattedRequests });
        }
    );
});

// ==================== АКТИВНОСТЬ ПОЛЬЗОВАТЕЛЯ ====================

// Управление активностью
app.put('/api/user/activity', requireAuth, (req, res) => {
    const { name, details, icon, color } = req.body;
    
    if (name && name.length > 100) {
        return res.status(400).json({ success: false, message: 'Название активности слишком длинное' });
    }

    if (details && details.length > 500) {
        return res.status(400).json({ success: false, message: 'Описание активности слишком длинное' });
    }

    db.run('DELETE FROM activities WHERE user_id = ?', [req.session.userId], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Ошибка сервера' });
        }
        
        if (name) {
            db.run(
                `INSERT INTO activities (user_id, name, details, icon, color)
                VALUES (?, ?, ?, ?, ?)`,
                [req.session.userId, name, details, icon, color],
                function(err) {
                    if (err) {
                        console.error('Database error:', err);
                        return res.status(500).json({ success: false, message: 'Ошибка сервера' });
                    }
                    
                    res.json({ 
                        success: true, 
                        message: 'Активность обновлена',
                        activity: { name, details, icon, color }
                    });
                }
            );
        } else {
            res.json({ 
                success: true, 
                message: 'Активность удалена'
            });
        }
    });
});

// ==================== СТАТИЧЕСКИЕ ФАЙЛЫ ====================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'auth.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'auth.html'));
});

app.get('/client', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'client.html'));
});

// Обработка 404
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Страница не найдена' });
});

// Обработка ошибок
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ success: false, message: 'Ошибка загрузки файла' });
    } else if (err.message === 'Only image files are allowed!') {
        return res.status(400).json({ success: false, message: 'Разрешены только изображения' });
    }
    
    res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});