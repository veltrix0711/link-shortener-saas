const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./links.db');

console.log('Checking user-created link...');
db.all("SELECT id, original_url, user_id, is_public FROM links WHERE custom_alias = 'user-test'", (err, rows) => {
  if (err) { 
    console.error('Error:', err); 
    return; 
  }
  console.log('User-created link:');
  rows.forEach(row => console.log(`- ID: ${row.id}, URL: ${row.original_url}, User ID: ${row.user_id}, Public: ${row.is_public}`));
  
  console.log('\nAll links in database:');
  db.all("SELECT id, custom_alias, user_id, is_public FROM links", (err, allRows) => {
    if (err) {
      console.error('Error fetching all links:', err);
    } else {
      allRows.forEach(row => console.log(`- ${row.id}: alias=${row.custom_alias}, user=${row.user_id}, public=${row.is_public}`));
    }
    db.close();
  });
});
