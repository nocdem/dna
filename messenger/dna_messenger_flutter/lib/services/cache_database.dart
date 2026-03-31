// Cache Database - SQLite storage for profile caching (contacts + identities)
import 'package:path/path.dart';
import 'package:sqflite/sqflite.dart';
import '../ffi/dna_engine.dart';

/// Starred message metadata
class StarredMessageInfo {
  final int messageId;
  final String contactFp;
  final DateTime starredAt;

  StarredMessageInfo({
    required this.messageId,
    required this.contactFp,
    required this.starredAt,
  });
}

/// Cached identity data (for identity selection screen)
class CachedIdentity {
  final String fingerprint;
  final String displayName;
  final String avatarBase64;
  final String registeredName; // DHT-registered DNA name (immutable)
  final DateTime cachedAt;

  CachedIdentity({
    required this.fingerprint,
    required this.displayName,
    required this.avatarBase64,
    this.registeredName = '',
    required this.cachedAt,
  });
}

/// SQLite database for caching profiles (contacts + identities)
class CacheDatabase {
  static const _databaseName = 'dna_cache.db';
  static const _databaseVersion = 6; // Bumped for pending_uploads table

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

    // Identity profiles cache table (for identity selection screen)
    await db.execute('''
      CREATE TABLE identity_profiles (
        fingerprint TEXT PRIMARY KEY,
        display_name TEXT,
        avatar_base64 TEXT,
        registered_name TEXT DEFAULT '',
        cached_at INTEGER
      )
    ''');

    // Identity list cache (fingerprints only - for fast startup)
    await db.execute('''
      CREATE TABLE identity_list (
        fingerprint TEXT PRIMARY KEY,
        order_index INTEGER
      )
    ''');

    // Starred messages table
    await db.execute('''
      CREATE TABLE starred_messages (
        message_id INTEGER PRIMARY KEY,
        contact_fp TEXT NOT NULL,
        starred_at INTEGER NOT NULL
      )
    ''');

    // Index for starred messages by contact
    await db.execute(
      'CREATE INDEX idx_starred_messages_contact ON starred_messages(contact_fp)'
    );

    // Pending media uploads (outbox — survives app restart)
    await db.execute('''
      CREATE TABLE pending_uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content_hash TEXT NOT NULL UNIQUE,
        recipient_fp TEXT NOT NULL,
        media_type INTEGER NOT NULL,
        mime_type TEXT NOT NULL,
        encrypted_file_path TEXT NOT NULL,
        encryption_key TEXT,
        thumbnail TEXT,
        caption TEXT,
        width INTEGER NOT NULL DEFAULT 0,
        height INTEGER NOT NULL DEFAULT 0,
        duration INTEGER NOT NULL DEFAULT 0,
        total_size INTEGER NOT NULL,
        chunk_count INTEGER NOT NULL,
        chunks_sent INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        error_message TEXT,
        retry_count INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    ''');

    await db.execute(
      'CREATE INDEX idx_pending_uploads_status ON pending_uploads(status)'
    );
  }

  Future<void> _onUpgrade(Database db, int oldVersion, int newVersion) async {
    // Alpha stage: drop and recreate all tables
    if (oldVersion < newVersion) {
      await db.execute('DROP TABLE IF EXISTS contact_profiles');
      await db.execute('DROP TABLE IF EXISTS identity_profiles');
      await db.execute('DROP TABLE IF EXISTS identity_list');
      await db.execute('DROP TABLE IF EXISTS starred_messages');
      await db.execute('DROP TABLE IF EXISTS pending_uploads');
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
  /// NOTE: displayName removed from UserProfile in v0.6.24 - use registered name from DHT
  Future<void> saveProfile(String fingerprint, UserProfile profile) async {
    final db = await database;
    final now = DateTime.now().millisecondsSinceEpoch;

    await db.insert(
      'contact_profiles',
      {
        'fingerprint': fingerprint,
        'display_name': '', // displayName removed - use registered name from DHT
        'bio': profile.bio,
        'location': profile.location,
        'website': profile.website,
        'avatar_base64': profile.avatarBase64,
        'backbone': profile.backbone,
        'alvin': profile.alvin,
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
  // Identity Profile Operations
  // ==========================================================================

  /// Get cached identity by fingerprint
  Future<CachedIdentity?> getIdentity(String fingerprint) async {
    final db = await database;
    final results = await db.query(
      'identity_profiles',
      where: 'fingerprint = ?',
      whereArgs: [fingerprint],
      limit: 1,
    );

    if (results.isEmpty) return null;
    return _rowToIdentity(results.first);
  }

  /// Get all cached identities
  Future<Map<String, CachedIdentity>> getAllIdentities() async {
    final db = await database;
    final results = await db.query('identity_profiles');

    final identities = <String, CachedIdentity>{};
    for (final row in results) {
      final fp = row['fingerprint'] as String;
      identities[fp] = _rowToIdentity(row);
    }
    return identities;
  }

  /// Save identity to cache
  Future<void> saveIdentity(String fingerprint, String displayName, String avatarBase64, {String registeredName = ''}) async {
    final db = await database;
    final now = DateTime.now().millisecondsSinceEpoch;

    await db.insert(
      'identity_profiles',
      {
        'fingerprint': fingerprint,
        'display_name': displayName,
        'avatar_base64': avatarBase64,
        'registered_name': registeredName,
        'cached_at': now,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  /// Save registered name only (without overwriting other fields)
  Future<void> saveRegisteredName(String fingerprint, String registeredName) async {
    final db = await database;
    final existing = await getIdentity(fingerprint);
    if (existing != null) {
      await db.update(
        'identity_profiles',
        {'registered_name': registeredName},
        where: 'fingerprint = ?',
        whereArgs: [fingerprint],
      );
    } else {
      await saveIdentity(fingerprint, '', '', registeredName: registeredName);
    }
  }

  /// Delete identity from cache
  Future<void> deleteIdentity(String fingerprint) async {
    final db = await database;
    await db.delete(
      'identity_profiles',
      where: 'fingerprint = ?',
      whereArgs: [fingerprint],
    );
  }

  /// Clear all cached identities
  Future<void> clearIdentities() async {
    final db = await database;
    await db.delete('identity_profiles');
  }

  /// Check if identity cache is stale
  Future<bool> isIdentityStale(String fingerprint, Duration maxAge) async {
    final db = await database;
    final cutoff = DateTime.now().subtract(maxAge).millisecondsSinceEpoch;
    final results = await db.query(
      'identity_profiles',
      columns: ['cached_at'],
      where: 'fingerprint = ? AND cached_at < ?',
      whereArgs: [fingerprint, cutoff],
      limit: 1,
    );
    return results.isNotEmpty;
  }

  CachedIdentity _rowToIdentity(Map<String, dynamic> row) {
    return CachedIdentity(
      fingerprint: row['fingerprint'] as String,
      displayName: row['display_name'] as String? ?? '',
      avatarBase64: row['avatar_base64'] as String? ?? '',
      registeredName: row['registered_name'] as String? ?? '',
      cachedAt: DateTime.fromMillisecondsSinceEpoch(row['cached_at'] as int? ?? 0),
    );
  }

  // ==========================================================================
  // Identity List Operations (for fast startup)
  // ==========================================================================

  /// Get cached identity list (fingerprints only)
  Future<List<String>> getIdentityList() async {
    final db = await database;
    final results = await db.query(
      'identity_list',
      orderBy: 'order_index ASC',
    );
    return results.map((row) => row['fingerprint'] as String).toList();
  }

  /// Save identity list to cache
  Future<void> saveIdentityList(List<String> fingerprints) async {
    final db = await database;

    // Clear existing and insert new
    await db.transaction((txn) async {
      await txn.delete('identity_list');
      for (int i = 0; i < fingerprints.length; i++) {
        await txn.insert('identity_list', {
          'fingerprint': fingerprints[i],
          'order_index': i,
        });
      }
    });
  }

  /// Clear identity list cache
  Future<void> clearIdentityList() async {
    final db = await database;
    await db.delete('identity_list');
  }

  // ==========================================================================
  // Starred Messages Operations
  // ==========================================================================

  /// Check if a message is starred
  Future<bool> isMessageStarred(int messageId) async {
    final db = await database;
    final results = await db.query(
      'starred_messages',
      where: 'message_id = ?',
      whereArgs: [messageId],
      limit: 1,
    );
    return results.isNotEmpty;
  }

  /// Get all starred message IDs for a contact
  Future<Set<int>> getStarredMessageIds(String contactFp) async {
    final db = await database;
    final results = await db.query(
      'starred_messages',
      columns: ['message_id'],
      where: 'contact_fp = ?',
      whereArgs: [contactFp],
    );
    return results.map((row) => row['message_id'] as int).toSet();
  }

  /// Get all starred message IDs
  Future<Set<int>> getAllStarredMessageIds() async {
    final db = await database;
    final results = await db.query(
      'starred_messages',
      columns: ['message_id'],
    );
    return results.map((row) => row['message_id'] as int).toSet();
  }

  /// Get all starred messages with metadata, grouped by contact
  /// Returns a map of contact fingerprint -> list of (messageId, starredAt)
  Future<Map<String, List<StarredMessageInfo>>> getAllStarredMessagesGrouped() async {
    final db = await database;
    final results = await db.query(
      'starred_messages',
      orderBy: 'starred_at DESC',
    );

    final grouped = <String, List<StarredMessageInfo>>{};
    for (final row in results) {
      final contactFp = row['contact_fp'] as String;
      final info = StarredMessageInfo(
        messageId: row['message_id'] as int,
        contactFp: contactFp,
        starredAt: DateTime.fromMillisecondsSinceEpoch(row['starred_at'] as int),
      );
      grouped.putIfAbsent(contactFp, () => []).add(info);
    }
    return grouped;
  }

  /// Star a message
  Future<void> starMessage(int messageId, String contactFp) async {
    final db = await database;
    final now = DateTime.now().millisecondsSinceEpoch;

    await db.insert(
      'starred_messages',
      {
        'message_id': messageId,
        'contact_fp': contactFp,
        'starred_at': now,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  /// Unstar a message
  Future<void> unstarMessage(int messageId) async {
    final db = await database;
    await db.delete(
      'starred_messages',
      where: 'message_id = ?',
      whereArgs: [messageId],
    );
  }

  /// Clear all starred messages for a contact
  Future<void> clearStarredMessages(String contactFp) async {
    final db = await database;
    await db.delete(
      'starred_messages',
      where: 'contact_fp = ?',
      whereArgs: [contactFp],
    );
  }

  // ==========================================================================
  // Helpers
  // ==========================================================================

  UserProfile _rowToProfile(Map<String, dynamic> row) {
    // NOTE: displayName removed from UserProfile in v0.6.24 - use registered name from DHT
    return UserProfile(
      bio: row['bio'] as String? ?? '',
      location: row['location'] as String? ?? '',
      website: row['website'] as String? ?? '',
      avatarBase64: row['avatar_base64'] as String? ?? '',
      backbone: row['backbone'] as String? ?? '',
      alvin: row['alvin'] as String? ?? '',
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

  // ==========================================================================
  // Pending Upload Operations (Media Outbox)
  // ==========================================================================

  /// Insert a new pending upload
  Future<int> insertPendingUpload(PendingUpload upload) async {
    final db = await database;
    return db.insert('pending_uploads', upload.toMap(),
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  /// Update chunks_sent for a content hash
  Future<void> updateChunksSent(String contentHash, int chunksSent) async {
    final db = await database;
    await db.update(
      'pending_uploads',
      {'chunks_sent': chunksSent, 'updated_at': DateTime.now().millisecondsSinceEpoch},
      where: 'content_hash = ?',
      whereArgs: [contentHash],
    );
  }

  /// Update upload status
  Future<void> updateUploadStatus(String contentHash, String status, [String? errorMessage]) async {
    final db = await database;
    final values = <String, Object?>{
      'status': status,
      'updated_at': DateTime.now().millisecondsSinceEpoch,
    };
    if (errorMessage != null) values['error_message'] = errorMessage;
    await db.update('pending_uploads', values,
        where: 'content_hash = ?', whereArgs: [contentHash]);
  }

  /// Increment retry count
  Future<void> incrementRetryCount(String contentHash) async {
    final db = await database;
    await db.rawUpdate(
      'UPDATE pending_uploads SET retry_count = retry_count + 1, updated_at = ? WHERE content_hash = ?',
      [DateTime.now().millisecondsSinceEpoch, contentHash],
    );
  }

  /// Get all pending/failed uploads for resume
  Future<List<PendingUpload>> getPendingUploads() async {
    final db = await database;
    final results = await db.query(
      'pending_uploads',
      where: "status IN ('pending', 'failed')",
      orderBy: 'created_at ASC',
    );
    return results.map(PendingUpload.fromMap).toList();
  }

  /// Get a specific pending upload by content hash
  Future<PendingUpload?> getPendingUpload(String contentHash) async {
    final db = await database;
    final results = await db.query(
      'pending_uploads',
      where: 'content_hash = ?',
      whereArgs: [contentHash],
    );
    if (results.isEmpty) return null;
    return PendingUpload.fromMap(results.first);
  }

  /// Delete a pending upload
  Future<void> deletePendingUpload(String contentHash) async {
    final db = await database;
    await db.delete('pending_uploads',
        where: 'content_hash = ?', whereArgs: [contentHash]);
  }

  /// Close the database
  Future<void> close() async {
    if (_database != null) {
      await _database!.close();
      _database = null;
    }
  }
}

/// Pending media upload data model
class PendingUpload {
  final int? id;
  final String contentHash;
  final String recipientFp;
  final int mediaType;
  final String mimeType;
  final String encryptedFilePath;
  final String? encryptionKey;
  final String? thumbnail;
  final String? caption;
  final int width;
  final int height;
  final int duration;
  final int totalSize;
  final int chunkCount;
  final int chunksSent;
  final String status;
  final String? errorMessage;
  final int retryCount;
  final DateTime createdAt;
  final DateTime updatedAt;

  PendingUpload({
    this.id,
    required this.contentHash,
    required this.recipientFp,
    required this.mediaType,
    required this.mimeType,
    required this.encryptedFilePath,
    this.encryptionKey,
    this.thumbnail,
    this.caption,
    this.width = 0,
    this.height = 0,
    this.duration = 0,
    required this.totalSize,
    required this.chunkCount,
    this.chunksSent = 0,
    this.status = 'pending',
    this.errorMessage,
    this.retryCount = 0,
    required this.createdAt,
    required this.updatedAt,
  });

  Map<String, Object?> toMap() => {
        'content_hash': contentHash,
        'recipient_fp': recipientFp,
        'media_type': mediaType,
        'mime_type': mimeType,
        'encrypted_file_path': encryptedFilePath,
        'encryption_key': encryptionKey,
        'thumbnail': thumbnail,
        'caption': caption,
        'width': width,
        'height': height,
        'duration': duration,
        'total_size': totalSize,
        'chunk_count': chunkCount,
        'chunks_sent': chunksSent,
        'status': status,
        'error_message': errorMessage,
        'retry_count': retryCount,
        'created_at': createdAt.millisecondsSinceEpoch,
        'updated_at': updatedAt.millisecondsSinceEpoch,
      };

  factory PendingUpload.fromMap(Map<String, dynamic> map) => PendingUpload(
        id: map['id'] as int?,
        contentHash: map['content_hash'] as String,
        recipientFp: map['recipient_fp'] as String,
        mediaType: map['media_type'] as int,
        mimeType: map['mime_type'] as String,
        encryptedFilePath: map['encrypted_file_path'] as String,
        encryptionKey: map['encryption_key'] as String?,
        thumbnail: map['thumbnail'] as String?,
        caption: map['caption'] as String?,
        width: map['width'] as int? ?? 0,
        height: map['height'] as int? ?? 0,
        duration: map['duration'] as int? ?? 0,
        totalSize: map['total_size'] as int,
        chunkCount: map['chunk_count'] as int,
        chunksSent: map['chunks_sent'] as int? ?? 0,
        status: map['status'] as String,
        errorMessage: map['error_message'] as String?,
        retryCount: map['retry_count'] as int? ?? 0,
        createdAt: DateTime.fromMillisecondsSinceEpoch(map['created_at'] as int),
        updatedAt: DateTime.fromMillisecondsSinceEpoch(map['updated_at'] as int),
      );
}
