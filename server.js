try {
  require('dotenv').config();
} catch (error) {
  // Abaikan dotenv di lingkungan serverless Vercel
}

process.on('uncaughtException', (err) => console.error('[CRASH] Uncaught Exception:', err));
process.on('unhandledRejection', (reason) => console.error('[CRASH] Unhandled Rejection:', reason));

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { GoogleGenAI, Type } = require('@google/genai');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Serve Halaman Utama (Frontend)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// KONEKSI DATABASE NEON POSTGRES
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('neon.tech') 
    ? { rejectUnauthorized: false } 
    : false
});

// AMAN DARI CRASH: Auto-update schema dimasukkan ke middleware non-blocking
let isSchemaUpdated = false;
async function initDbSchema() {
  if (isSchemaUpdated || !process.env.DATABASE_URL) return;
  try {
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(255);
      
      CREATE TABLE IF NOT EXISTS payments (
          id SERIAL PRIMARY KEY,
          user_id UUID REFERENCES users(id) ON DELETE CASCADE,
          amount INTEGER,
          method VARCHAR(50),
          status VARCHAR(50),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    isSchemaUpdated = true;
    console.log('✅ Database schema & payments table verified.');
  } catch (err) {
    console.error('❌ DB Schema update error (dilewati agar server tidak crash):', err.message);
  }
}

app.use(async (req, res, next) => {
  await initDbSchema();
  next();
});

const upload = multer({ storage: multer.memoryStorage() });
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });
const JWT_SECRET = process.env.JWT_SECRET || 'speakeasy_cocktail_secret_key_2026';

// HELPER FUNCTIONS
async function saveRecipesToDatabase(userId, sourceBookName, recipesList) {
  const savedRecipes = [];
  for (const recipe of recipesList) {
    const recipeResult = await pool.query(
      `INSERT INTO recipes (user_id, name, glassware, category, instructions, is_complete, source_book)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name`,
      [userId, recipe.recipe_name, recipe.glassware, recipe.category, recipe.instructions, recipe.is_complete, sourceBookName]
    );
    const insertedRecipe = recipeResult.rows[0];

    for (const ing of recipe.ingredients) {
      const ingResult = await pool.query(
        `INSERT INTO ingredients (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`,
        [ing.name]
      );
      const ingredientObj = ingResult.rows[0];
      await pool.query(
        `INSERT INTO recipe_ingredients (recipe_id, ingredient_id, amount, unit, raw_name) VALUES ($1, $2, $3, $4, $5)`,
        [insertedRecipe.id, ingredientObj.id, ing.amount, ing.unit, ing.name]
      );
    }
    savedRecipes.push(insertedRecipe);
  }
  return savedRecipes;
}

async function extractRecipesFromPdf(pdfBuffer) {
  const pdfBase64 = pdfBuffer.toString('base64');
  const modelCandidates = ['gemini-2.5-flash', 'gemini-1.5-flash'];
  const contents = [
    { inlineData: { mimeType: 'application/pdf', data: pdfBase64 } },
    'Extract all cocktail recipes from this PDF document into a JSON array according to the schema.'
  ];
  const config = {
    responseMimeType: 'application/json',
    responseSchema: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          recipe_name: { type: Type.STRING },
          glassware: { type: Type.STRING },
          category: { type: Type.STRING },
          ingredients: { type: Type.ARRAY, items: { type: Type.OBJECT, properties: { name: { type: Type.STRING }, amount: { type: Type.NUMBER }, unit: { type: Type.STRING } }, required: ['name', 'amount', 'unit'] } },
          instructions: { type: Type.ARRAY, items: { type: Type.STRING } },
          is_complete: { type: Type.BOOLEAN }
        },
        required: ['recipe_name', 'glassware', 'category', 'instructions', 'is_complete']
      }
    }
  };

  let lastError;
  for (const modelName of modelCandidates) {
    try {
      const response = await ai.models.generateContent({ model: modelName, contents: contents, config: config });
      return response.text;
    } catch (err) { lastError = err; }
  }
  throw lastError;
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token found.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user; next();
  });
}

// === AUTH ENDPOINTS ===
app.post('/api/auth/register', async (req, res) => {
  const { email, password, full_name, username } = req.body;
  if (!email || !password || !full_name || !username) return res.status(400).json({ error: 'Mohon lengkapi semua data pendaftaran.' });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
        `INSERT INTO users (email, password_hash, full_name, username) VALUES ($1, $2, $3, $4) RETURNING id, email, full_name, username`, 
        [email, hashedPassword, full_name, username]
    );
    return res.status(201).json({ message: 'Registrasi berhasil', user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') return res.status(400).json({ error: 'Email/Username sudah digunakan.' });
    return res.status(500).json({ error: 'Registrasi gagal: ' + error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(`SELECT id, email, password_hash, full_name, username FROM users WHERE email = $1 OR username = $1`, [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email/Username atau password salah.' });
    const token = jwt.sign({ userId: user.id, email: user.email, name: user.full_name }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ message: 'Login berhasil', token, user: { id: user.id, email: user.email, name: user.full_name } });
  } catch (error) { return res.status(500).json({ error: 'Login gagal: ' + error.message }); }
});

// === PAYMENT ENDPOINTS ===
app.post('/api/payments/pay', authenticateToken, async (req, res) => {
  try {
      const { amount, method } = req.body;
      await pool.query(
          `INSERT INTO payments (user_id, amount, method, status) VALUES ($1, $2, $3, $4)`,
          [req.user.userId, amount, method, 'SUCCESS']
      );
      res.json({ success: true, message: 'Payment recorded.' });
  } catch(error) {
      res.status(500).json({ error: error.message });
  }
});

// === ADMIN ENDPOINTS ===
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  try {
      const result = await pool.query(`
          SELECT u.id, u.full_name, u.email, u.username, COALESCE(SUM(p.amount), 0) as total_paid
          FROM users u 
          LEFT JOIN payments p ON u.id = p.user_id
          GROUP BY u.id 
          ORDER BY u.full_name ASC
      `);
      res.json({ success: true, users: result.rows });
  } catch(error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/recipes/import-pdf', authenticateToken, upload.single('pdf'), async (req, res) => {
  try {
    const jsonText = await extractRecipesFromPdf(req.file.buffer);
    const savedData = await saveRecipesToDatabase(req.user.userId, req.body.book_title || req.file.originalname, JSON.parse(jsonText));
    return res.status(201).json({ success: true, message: `${savedData.length} recipes extracted and saved!`, saved_recipes: savedData });
  } catch (error) { return res.status(500).json({ error: 'Failed to process PDF: ' + error.message }); }
});

app.post('/api/recipes/add-manual', authenticateToken, async (req, res) => {
  try {
    const { recipe } = req.body;
    await saveRecipesToDatabase(req.user.userId, "My Original Creations", [recipe]);
    return res.json({ success: true, message: `Resep berhasil ditambahkan!` });
  } catch (error) { return res.status(500).json({ error: error.message }); }
});

app.post('/api/recipes/edit/:id', authenticateToken, async (req, res) => {
  try {
    const recipeId = req.params.id;
    const { recipe } = req.body;
    await pool.query(`UPDATE recipes SET name = $1, category = $2, glassware = $3, instructions = $4 WHERE id = $5 AND user_id = $6`, [recipe.recipe_name, recipe.category, recipe.glassware, recipe.instructions, recipeId, req.user.userId]);
    await pool.query(`DELETE FROM recipe_ingredients WHERE recipe_id = $1`, [recipeId]);
    for (const ing of recipe.ingredients) {
      const ingResult = await pool.query(`INSERT INTO ingredients (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`, [ing.name]);
      await pool.query(`INSERT INTO recipe_ingredients (recipe_id, ingredient_id, amount, unit, raw_name) VALUES ($1, $2, $3, $4, $5)`, [recipeId, ingResult.rows[0].id, ing.amount, ing.unit, ing.name]);
    }
    return res.json({ success: true, message: "Resep berhasil diperbarui!" });
  } catch (error) { return res.status(500).json({ error: error.message }); }
});

app.get('/api/recipes', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`SELECT r.id, r.name, r.glassware, r.category, r.instructions, r.source_book, json_agg(json_build_object('name', i.name, 'amount', ri.amount, 'unit', ri.unit)) AS ingredients FROM recipes r LEFT JOIN recipe_ingredients ri ON r.id = ri.recipe_id LEFT JOIN ingredients i ON ri.ingredient_id = i.id WHERE r.user_id = $1 GROUP BY r.id`, [req.user.userId]);
    return res.json({ success: true, recipes: result.rows });
  } catch (error) { return res.status(500).json({ error: error.message }); }
});

app.post('/api/recipes/recommend', authenticateToken, async (req, res) => {
  const { ingredients } = req.body;
  try {
    const result = await pool.query(`SELECT r.id, r.name, r.glassware, r.category, r.instructions, r.source_book, json_agg(json_build_object('name', i.name, 'amount', ri.amount, 'unit', ri.unit)) AS ingredients FROM recipes r JOIN recipe_ingredients ri ON r.id = ri.recipe_id JOIN ingredients i ON ri.ingredient_id = i.id WHERE r.user_id = $1 GROUP BY r.id`, [req.user.userId]);
    const userStock = ingredients.map(ing => ing.toLowerCase().trim());
    const recommendations = result.rows.map(recipe => {
      const matched = [];
      recipe.ingredients.forEach(ing => { if (userStock.some(stock => ing.name.toLowerCase().includes(stock) || stock.includes(ing.name.toLowerCase()))) matched.push(ing.name); });
      return { ...recipe, match_percentage: Math.round((matched.length / recipe.ingredients.length) * 100), matched_ingredients: matched, all_ingredients: recipe.ingredients };
    });
    return res.json({ success: true, recommendations: recommendations.sort((a, b) => b.match_percentage - a.match_percentage) });
  } catch (error) { return res.status(500).json({ error: error.message }); }
});

app.get('/api/recipes/global-search', authenticateToken, async (req, res) => {
  try {
    const response = await fetch(`https://www.thecocktaildb.com/api/json/v1/1/search.php?s=${req.query.q}`);
    const data = await response.json();
    if (!data.drinks) return res.json({ success: true, recipes: [] });
    const formattedRecipes = data.drinks.map(drink => {
      const ingredients = [];
      for (let i = 1; i <= 15; i++) if (drink[`strIngredient${i}`]?.trim()) ingredients.push({ name: drink[`strIngredient${i}`].trim(), amount: drink[`strMeasure${i}`]?.trim() || "To taste", unit: "" });
      return { id: drink.idDrink, name: drink.strDrink, glassware: drink.strGlass, category: drink.strCategory, instructions: [drink.strInstructions], ingredients, source_book: "Global Database", match_percentage: 100, image: drink.strDrinkThumb };
    });
    return res.json({ success: true, recipes: formattedRecipes });
  } catch (error) { return res.status(500).json({ error: error.message }); }
});

app.post('/api/recipes/save-global', authenticateToken, async (req, res) => {
  try {
    const { recipe } = req.body;
    await saveRecipesToDatabase(req.user.userId, recipe.source_book, [{ recipe_name: recipe.name, glassware: recipe.glassware, category: recipe.category, ingredients: recipe.ingredients, instructions: recipe.instructions, is_complete: true }]);
    return res.json({ success: true, message: `"${recipe.name}" saved to local vault!` });
  } catch (error) { return res.status(500).json({ error: error.message }); }
});

// === PUBLIC ENDPOINTS ===
app.get('/api/public/recipes', async (req, res) => {
  try {
    const result = await pool.query(`SELECT r.id, r.name, r.glassware, r.category, r.instructions, r.source_book, json_agg(json_build_object('name', i.name, 'amount', ri.amount, 'unit', ri.unit)) AS ingredients FROM recipes r LEFT JOIN recipe_ingredients ri ON r.id = ri.recipe_id LEFT JOIN ingredients i ON ri.ingredient_id = i.id GROUP BY r.id`);
    return res.json({ success: true, recipes: result.rows });
  } catch (error) { return res.status(500).json({ error: error.message }); }
});

app.post('/api/public/recommend', async (req, res) => {
  const { ingredients } = req.body;
  try {
    const result = await pool.query(`SELECT r.id, r.name, r.glassware, r.category, r.instructions, r.source_book, json_agg(json_build_object('name', i.name, 'amount', ri.amount, 'unit', ri.unit)) AS ingredients FROM recipes r JOIN recipe_ingredients ri ON r.id = ri.recipe_id JOIN ingredients i ON ri.ingredient_id = i.id GROUP BY r.id`);
    const userStock = ingredients.map(ing => ing.toLowerCase().trim());
    const recommendations = result.rows.map(recipe => {
      const matched = [];
      recipe.ingredients.forEach(ing => { if (userStock.some(stock => ing.name.toLowerCase().includes(stock) || stock.includes(ing.name.toLowerCase()))) matched.push(ing.name); });
      return { ...recipe, match_percentage: Math.round((matched.length / recipe.ingredients.length) * 100), matched_ingredients: matched, all_ingredients: recipe.ingredients };
    });
    return res.json({ success: true, recommendations: recommendations.sort((a, b) => b.match_percentage - a.match_percentage) });
  } catch (error) { return res.status(500).json({ error: error.message }); }
});

app.get('/api/public/global-search', async (req, res) => {
  try {
    const response = await fetch(`https://www.thecocktaildb.com/api/json/v1/1/search.php?s=${req.query.q}`);
    const data = await response.json();
    if (!data.drinks) return res.json({ success: true, recipes: [] });
    const formattedRecipes = data.drinks.map(drink => {
      const ingredients = [];
      for (let i = 1; i <= 15; i++) if (drink[`strIngredient${i}`]?.trim()) ingredients.push({ name: drink[`strIngredient${i}`].trim(), amount: drink[`strMeasure${i}`]?.trim() || "To taste", unit: "" });
      return { id: drink.idDrink, name: drink.strDrink, glassware: drink.strGlass, category: drink.strCategory, instructions: [drink.strInstructions], ingredients, source_book: "Global Database", match_percentage: 100, image: drink.strDrinkThumb };
    });
    return res.json({ success: true, recipes: formattedRecipes });
  } catch (error) { return res.status(500).json({ error: error.message }); }
});

// LISTEN HANYA JIKA DIBUKA DI LAPTOP (Bukan di Cloud Vercel)
if (!process.env.VERCEL && process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`🚀 Cocktail AI Server running on port ${PORT}`));
}

// EXPORT WAJIB UNTUK VERCEL SERVERLESS
module.exports = app;
