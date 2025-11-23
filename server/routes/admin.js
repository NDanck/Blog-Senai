const express = require('express');
const router = express.Router();
const Post = require('../models/Post');
const Category = require('../models/Category');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const upload = require('../middleware/upload');

const adminLayout = '../views/layouts/admin';
const jwtSecret = process.env.JWT_SECRET;

const authMiddleware = (req, res, next ) => {
  const token = req.cookies.token;

  if(!token) {
    return res.status(401).json( { message: 'Unauthorized'} );
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.userId = decoded.userId;
    next();
  } catch(error) {
    res.status(401).json( { message: 'Unauthorized'} );
  }
}



router.get('/login', async (req, res) => {
  try {
    const locals = {
      title: "Log-In",
      description: "Blog com as ultimas noticias da industria."
    }
    const rememberedUser = req.cookies.remember_user || "";

    res.render('admin/index', { locals, layout: adminLayout, rememberedUser });
  } catch (error) {
  }
});



router.post('/login', async (req, res) => {
  try {
    const { username, password, remember } = req.body;
    
    const user = await User.findOne( { username } );

    if(!user) {
      return res.status(401).json( { message: 'Invalid credentials' } );
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if(!isPasswordValid) {
      return res.status(401).json( { message: 'Invalid credentials' } );
    }

    if (remember) {
    res.cookie("remember_user", username, {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true
    });
    } else {
        res.clearCookie("remember_user");
    }

    const token = jwt.sign({ userId: user._id}, jwtSecret );
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/dashboard');

  } catch (error) {
    console.log(error);
  }
});



router.get('/dashboard', authMiddleware, async (req, res) => {
  try {
    const locals = {
      title: 'Dashboard',
      description: 'Blog com as ultimas noticias da industria.'
    }

    const posts = await Post.find();
    const users = await User.find();
    const categories = await Category.find();
    res.render('admin/dashboard', {
      layout: adminLayout,
      locals,
      posts,
      users,
      categories
    });

  } catch (error) {
    console.log(error);
  }

});



router.get('/add-post', authMiddleware, async (req, res) => {
  try {
    const locals = {
      title: 'Add Post',
      description: 'Blog com as ultimas noticias da industria.'
    }

    const categories = await Category.find();

    res.render('admin/add-post', {
      layout: adminLayout,
      categories,
      locals,
    });

  } catch (error) {
    console.log(error);
  }

});




router.post('/add-post', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const newPost = new Post({
      title: req.body.title,
      body: req.body.body,
      category: req.body.category || null,
      image: req.file ? req.file.filename : null
    });

    await newPost.save();
    res.redirect('/dashboard');

  } catch (error) {
    console.log(error);
  }
});



router.get('/edit-post/:id', authMiddleware, async (req, res) => {
  try {

    const locals = {
      title: "Edit Post",
      description: "Blog com as ultimas noticias da industria.",
    };

    const data = await Post.findOne({ _id: req.params.id });

    const categories = await Category.find();

    res.render('admin/edit-post', {
      layout: adminLayout,
      locals,
      data,
      categories
    })

  } catch (error) {
    console.log(error);
  }

});



router.put('/edit-post/:id', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const updateData = {
      title: req.body.title,
      body: req.body.body,
      category: req.body.category || null,
      updatedAt: Date.now()
    };

    if (req.file) {
      updateData.image = req.file.filename;
    }

    await Post.findByIdAndUpdate(req.params.id, updateData);

    res.redirect('/dashboard');

  } catch (err) {
    console.log(err);
  }
});




router.post('/register', async (req, res) => {
  try {
    const { username_registro, password_registro } = req.body;
    const hashedPassword = await bcrypt.hash(password_registro, 10);

    try {
      const user = await User.create({ username: username_registro, password:hashedPassword });
      res.redirect('/dashboard');
    } catch (error) {
      if(error.code === 11000) {
        res.status(409).json({ message: 'User already in use'});
      }
      res.status(500).json({ message: 'Internal server error'})
    }

  } catch (error) {
    console.log(error);
  }
});



router.delete('/delete-post/:id', authMiddleware, async (req, res) => {

  try {
    await Post.deleteOne( { _id: req.params.id } );
    res.redirect('/dashboard');
  } catch (error) {
    console.log(error);
  }

});



router.get('/add-user', authMiddleware, async (req, res) => {
  try {
    const locals = {
      title: 'Add User',
      description: 'Blog com as ultimas noticias da industria.'
    }

    res.render('admin/add-user', {
      locals,
      layout: adminLayout
    });

  } catch (error) {
    console.log(error);
  }

});



router.get('/edit-user/:id', authMiddleware, async (req, res) => {
  try {

    const locals = {
      title: "Edit User",
      description: "Blog com as ultimas noticias da industria.",
    };

    const data = await User.findOne({ _id: req.params.id });

    res.render('admin/edit-user', {
      locals,
      data,
      layout: adminLayout
    })

  } catch (error) {
    console.log(error);
  }

});



router.put('/edit-user/:id', authMiddleware, async (req, res) => {
  try {

    const hashedPassword = await bcrypt.hash(req.body.password_registro, 10);
    const updateData = {
      username: req.body.username_registro,
      password: hashedPassword,
      updatedAt: Date.now()
    };

    await User.findByIdAndUpdate(req.params.id, updateData);

    res.redirect('/dashboard');

  } catch (err) {
    console.log(err);
  }
});



router.delete('/delete-user/:id', authMiddleware, async (req, res) => {

  try {
    await User.deleteOne( { _id: req.params.id } );
    res.redirect('/dashboard');
  } catch (error) {
    console.log(error);
  }

});



router.get('/add-category', authMiddleware, async (req, res) => {
  try {
    const locals = {
      title: 'Add Category',
      description: 'Blog com as ultimas noticias da industria.'
    }

    res.render('admin/add-category', {
      locals,
      layout: adminLayout
    });

  } catch (error) {
    console.log(error);
  }

});




router.post('/add-category', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const newCategory = new Category({
      name: req.body.name,
    });

    await newCategory.save();
    res.redirect('/dashboard');

  } catch (error) {
    console.log(error);
  }
});



router.get('/edit-category/:id', authMiddleware, async (req, res) => {
  try {

    const locals = {
      title: "Edit Category",
      description: "Blog com as ultimas noticias da industria.",
    };

    const data = await Category.findOne({ _id: req.params.id });

    res.render('admin/edit-category', {
      locals,
      data,
      layout: adminLayout
    })

  } catch (error) {
    console.log(error);
  }

});



router.put('/edit-category/:id', authMiddleware, async (req, res) => {
  try {
    const updateData = {
      name: req.body.name,
      updatedAt: Date.now()
    };

    console.log(req.body.name)

    await Category.findByIdAndUpdate(req.params.id, updateData);

    res.redirect('/dashboard');

  } catch (err) {
    console.log(err);
  }
});




router.delete('/delete-category/:id', authMiddleware, async (req, res) => {

  try {
    await Category.deleteOne( { _id: req.params.id } );
    res.redirect('/dashboard');
  } catch (error) {
    console.log(error);
  }

});



router.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});


module.exports = router;