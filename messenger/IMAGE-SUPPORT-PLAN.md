# Image Support Implementation Plan

## Goal
Add basic support for sending and displaying inline images in DNA Messenger.

## Approach
**Embed images as base64 in message text** (simplest MVP approach)

### Message Format
```
For text-only messages:
"Hello world!"

For messages with images:
"Check this out!\n[IMG:data:image/png;base64,iVBORw0KGgoAAAANSUhEUg...]"

Multiple images:
"Photo 1:\n[IMG:base64...]\nPhoto 2:\n[IMG:base64...]"
```

## Implementation Steps

### 1. Backend (messenger.c) - Minimal Changes
- No changes needed! Messages already support arbitrary text
- Images are just base64-encoded strings in the message
- Max message size already supports large payloads

### 2. GUI (MainWindow.cpp) - Image Display
- Parse message text for [IMG:data:...] markers
- Decode base64 to QPixmap
- Display inline in QTextEdit using HTML `<img>` tags with data URIs
- Add image size limits (e.g., 5MB max per image)

### 3. GUI - Image Sending
- Add "Attach Image" button (📎 icon)
- File picker for .png, .jpg, .jpeg, .gif, .webp
- Resize large images (e.g., max 1920x1080)
- Compress to reasonable quality
- Convert to base64
- Append to message text

## Advantages of This Approach
✅ No database schema changes
✅ No new message types
✅ Works with existing encryption
✅ Simple to implement
✅ Backward compatible (old clients see base64 text)
✅ Forward compatible (can migrate to binary later)

## Limitations
- Messages with images will be larger
- Base64 encoding adds ~33% overhead
- Not ideal for many/large images
- Full image loaded in memory

## Future Improvements (Later)
- Store images separately (filesystem or DB)
- Reference images by ID/hash
- Progressive image loading
- Thumbnails
- Image compression options
- Video support

## Implementation Priority
1. GUI image display (parse and show)
2. GUI image sending (attach button)
3. Image size/format validation
4. Resize/compress large images
5. Multiple image support

## File Size Limits
- Max single image: 5MB (before base64)
- Max message size: 10MB (after base64)
- Recommended: 1920x1080 max resolution
- Auto-resize if larger

