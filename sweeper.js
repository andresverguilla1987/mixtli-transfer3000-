
import 'dotenv/config'
import { S3Client, DeleteObjectCommand } from '@aws-sdk/client-s3'
import pg from 'pg'

const { DATABASE_URL, S3_ENDPOINT, S3_REGION='auto', S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_FORCE_PATH_STYLE='true' } = process.env

const pool = new pg.Pool({ connectionString: DATABASE_URL })
const s3 = new S3Client({
  region: S3_REGION,
  endpoint: S3_ENDPOINT,
  credentials: { accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY },
  forcePathStyle: String(S3_FORCE_PATH_STYLE).toLowerCase() === 'true',
})

async function run(){
  const client = await pool.connect()
  try{
    const { rows } = await client.query(`SELECT id,key FROM links WHERE active=true AND expires_at < now() LIMIT 500`)
    for(const r of rows){
      try{ await s3.send(new DeleteObjectCommand({ Bucket:S3_BUCKET, Key:r.key })) }catch(e){ /* ignore */ }
      await client.query('UPDATE links SET active=false WHERE id=$1', [r.id])
    }
    console.log('expired cleaned:', rows.length)
  } finally { client.release() }
}
run().then(()=>process.exit(0)).catch(e=>{ console.error(e); process.exit(1) })
