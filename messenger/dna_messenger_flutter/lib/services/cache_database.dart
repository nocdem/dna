// Cache Database - SQLite storage for contact profile caching
import 'dart:convert';
import 'package:path/path.dart';
import 'package:sqflite/sqflite.dart';
import '../ffi/dna_engine.dart';

/// SQLite database for caching contact profiles
class CacheDatabase {
  static const _databaseName = 'dna_cache.db';
  static const _databaseVersion = 1;

  // Singleton instance
  static CacheDatabase? _instance;
  static Database? _database;

  CacheDatabase._();

  static CacheDatabase get instance {
    _instance ??= CacheDatabase._();
    return _instance!;
  }

  Future<Database> get database async {
    _database ??= await _initDatabase();
    return _database!;
  }

  Future<Database> _initDatabase() async {
    final dbPath = await getDatabasesPath();
    final path = join(dbPath, _databaseName);

    return await openDatabase(
      path,
      version: _databaseVersion,
      onCreate: _onCreate,
      onUpgrade: _onUpgrade,
    );
  }

  Future<void> _onCreate(Database db, int version) async {
    // Contact profiles cache table
    await db.execute('''
      CREATE TABLE contact_profiles (
        fingerprint TEXT PRIMARY KEY,
        display_name TEXT,
        bio TEXT,
        location TEXT,
        website TEXT,
        avatar_base64 TEXT,
        backbone TEXT,
        alvin TEXT,
        btc TEXT,
        eth TEXT,
        sol TEXT,
        trx TEXT,
        telegram TEXT,
        twitter TEXT,
        github TEXT,
        facebook TEXT,
        instagram TEXT,
        linkedin TEXT,
        google TEXT,
        cached_at INTEGER,
        updated_at INTEGER
      )
    ''');

    // Index for quick lookups
    await db.execute(
      'CREATE INDEX idx_contact_profiles_cached_at ON contact_profiles(cached_at)'
    );
  }

  Future<void> _onUpgrade(Database db, int oldVersion, int newVersion) async {
    // Handle future schema migrations here
    if (oldVersion < newVersion) {
      // Drop and recreate for now (alpha stage)
      await db.execute('DROP TABLE IF EXISTS contact_profiles');
      await _onCreate(db, newVersion);
    }
  }

  // ==========================================================================
  // Contact Profile Operations
  // ==========================================================================

  /// Get cached profile by fingerprint
  Future<UserProfile?> getProfile(String fingerprint) async {
    final db = await database;
    final results = await db.query(
      'contact_profiles',
      where: 'fingerprint = ?',
      whereArgs: [fingerprint],
      limit: 1,
    );

    if (results.isEmpty) return null;

    return _rowToProfile(results.first);
  }

  /// Get multiple cached profiles
  Future<Map<String, UserProfile>> getProfiles(List<String> fingerprints) async {
    if (fingerprints.isEmpty) return {};

    final db = await database;
    final placeholders = List.filled(fingerprints.length, '?').join(',');
    final results = await db.query(
      'contact_profiles',
      where: 'fingerprint IN ($placeholders)',
      whereArgs: fingerprints,
    );

    final profiles = <String, UserProfile>{};
    for (final row in results) {
      final fp = row['fingerprint'] as String;
      profiles[fp] = _rowToProfile(row);
    }
    return profiles;
  }

  /// Get all cached profiles
  Future<Map<String, UserProfile>> getAllProfiles() async {
    final db = await database;
    final results = await db.query('contact_profiles');

    final profiles = <String, UserProfile>{};
    for (final row in results) {
      final fp = row['fingerprint'] as String;
      profiles[fp] = _rowToProfile(row);
    }
    return profiles;
  }

  /// Save profile to cache
  Future<void> saveProfile(String fingerprint, UserProfile profile) async {
    final db = await database;
    final now = DateTime.now().millisecondsSinceEpoch;

    await db.insert(
      'contact_profiles',
      {
        'fingerprint': fingerprint,
        'display_name': profile.displayName,
        'bio': profile.bio,
        'location': profile.location,
        'website': profile.website,
        'avatar_base64': profile.avatarBase64,
        'backbone': profile.backbone,
        'alvin': profile.alvin,
        'btc': profile.btc,
        'eth': profile.eth,
        'sol': profile.sol,
        'trx': profile.trx,
        'telegram': profile.telegram,
        'twitter': profile.twitter,
        'github': profile.github,
        'facebook': profile.facebook,
        'instagram': profile.instagram,
        'linkedin': profile.linkedin,
        'google': profile.google,
        'cached_at': now,
        'updated_at': now,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  /// Delete profile from cache
  Future<void> deleteProfile(String fingerprint) async {
    final db = await database;
    await db.delete(
      'contact_profiles',
      where: 'fingerprint = ?',
      whereArgs: [fingerprint],
    );
  }

  /// Clear all cached profiles
  Future<void> clearProfiles() async {
    final db = await database;
    await db.delete('contact_profiles');
  }

  /// Delete profiles older than maxAge
  Future<int> cleanupOldProfiles(Duration maxAge) async {
    final db = await database;
    final cutoff = DateTime.now().subtract(maxAge).millisecondsSinceEpoch;
    return await db.delete(
      'contact_profiles',
      where: 'cached_at < ?',
      whereArgs: [cutoff],
    );
  }

  /// Check if profile is stale (older than maxAge)
  Future<bool> isProfileStale(String fingerprint, Duration maxAge) async {
    final db = await database;
    final cutoff = DateTime.now().subtract(maxAge).millisecondsSinceEpoch;
    final results = await db.query(
      'contact_profiles',
      columns: ['cached_at'],
      where: 'fingerprint = ? AND cached_at < ?',
      whereArgs: [fingerprint, cutoff],
      limit: 1,
    );
    return results.isNotEmpty;
  }

  // ==========================================================================
  // Helpers
  // ==========================================================================

  UserProfile _rowToProfile(Map<String, dynamic> row) {
    return UserProfile(
      displayName: row['display_name'] as String? ?? '',
      bio: row['bio'] as String? ?? '',
      location: row['location'] as String? ?? '',
      website: row['website'] as String? ?? '',
      avatarBase64: row['avatar_base64'] as String? ?? '',
      backbone: row['backbone'] as String? ?? '',
      alvin: row['alvin'] as String? ?? '',
      btc: row['btc'] as String? ?? '',
      eth: row['eth'] as String? ?? '',
      sol: row['sol'] as String? ?? '',
      trx: row['trx'] as String? ?? '',
      telegram: row['telegram'] as String? ?? '',
      twitter: row['twitter'] as String? ?? '',
      github: row['github'] as String? ?? '',
      facebook: row['facebook'] as String? ?? '',
      instagram: row['instagram'] as String? ?? '',
      linkedin: row['linkedin'] as String? ?? '',
      google: row['google'] as String? ?? '',
    );
  }

  /// Close the database
  Future<void> close() async {
    if (_database != null) {
      await _database!.close();
      _database = null;
    }
  }
}
