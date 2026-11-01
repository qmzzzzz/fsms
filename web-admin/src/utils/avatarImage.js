/**
 * 头像前端处理：中心方形裁切 + 压缩
 *
 * 与服务端 utils/avatarImage.js 的 256 KB 上限对齐：data URI 超过 400000 字符
 * 直接换更低质量/更小尺寸重试，而不是让用户上传后才收到 400。
 */

/** 源文件上限：手机原图常见 3–6 MB，给了 5 MB 的余量，超过直接提示换图 */
export const MAX_SOURCE_BYTES = 5 * 1024 * 1024
/** 与后端 MAX_DATA_URI_CHARS 必须一致 */
export const MAX_DATA_URI_CHARS = 400000
export const AVATAR_SIZE = 512
export const AVATAR_QUALITY = 0.85

/** 中心方形裁切矩形（纯函数，单测直接调） */
export const getCenterSquare = (width, height) => {
  const w = Number(width)
  const h = Number(height)
  if (!Number.isFinite(w) || !Number.isFinite(h) || w <= 0 || h <= 0) {
    return { sx: 0, sy: 0, side: 0 }
  }
  const side = Math.floor(Math.min(w, h))
  return { sx: Math.floor((w - side) / 2), sy: Math.floor((h - side) / 2), side }
}

export const isSupportedAvatarType = (type) => type === 'image/jpeg' || type === 'image/png'

const renderToDataUrl = (image, size, quality) => {
  const { sx, sy, side } = getCenterSquare(image.naturalWidth, image.naturalHeight)
  const canvas = document.createElement('canvas')
  canvas.width = size
  canvas.height = size
  const context = canvas.getContext('2d')
  // PNG 透明区域在 JPEG 上会变黑：先铺白底
  context.fillStyle = '#ffffff'
  context.fillRect(0, 0, size, size)
  context.drawImage(image, sx, sy, side, side, 0, 0, size, size)
  return canvas.toDataURL('image/jpeg', quality)
}

/**
 * 读取文件 → 中心裁切 → 512×512 JPEG
 * @returns {Promise<{dataUrl: string, width: number, height: number}>}
 */
export const compressAvatarFile = (file, { size = AVATAR_SIZE, quality = AVATAR_QUALITY } = {}) => {
  return new Promise((resolve, reject) => {
    if (!file || !isSupportedAvatarType(file.type)) {
      reject(new Error('invalidType'))
      return
    }
    if (file.size > MAX_SOURCE_BYTES) {
      reject(new Error('tooLarge'))
      return
    }
    const objectUrl = URL.createObjectURL(file)
    const image = new Image()
    image.onload = () => {
      try {
        let dataUrl = renderToDataUrl(image, size, quality)
        if (dataUrl.length > MAX_DATA_URI_CHARS) {
          dataUrl = renderToDataUrl(image, size, 0.7)
        }
        if (dataUrl.length > MAX_DATA_URI_CHARS) {
          dataUrl = renderToDataUrl(image, 384, 0.75)
        }
        if (dataUrl.length > MAX_DATA_URI_CHARS) {
          reject(new Error('tooLarge'))
          return
        }
        resolve({ dataUrl, width: size, height: size })
      } catch (error) {
        reject(error)
      } finally {
        URL.revokeObjectURL(objectUrl)
      }
    }
    image.onerror = () => {
      URL.revokeObjectURL(objectUrl)
      reject(new Error('invalidImage'))
    }
    image.src = objectUrl
  })
}
