#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map,xdp},
    programs::XdpContext,
    helpers::bpf_ktime_get_ns,
    maps::{Array,HashMap, PerCpuHashMap}, bpf_printk,
};
use aya_log_ebpf::{info,error};
use core::{mem::{self, transmute}, u32, hash};


use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use xxhash_rust::const_xxh32::xxh32 as const_xxh32;
use xxhash_rust::xxh32::xxh32;

const CMS_SIZE:u32 = 131072;
const CMS_ROWS:u32 = 5;
// // array-one-entry
#[derive(Clone, Copy)]
pub struct Cms {
    cms: [[u16; CMS_SIZE as usize]; CMS_ROWS as usize], 
}
#[map]
static CMS_ARRAY: Array::<Cms> = Array::<Cms>::with_max_entries(1, 0);
// array-of-rows
// #[derive(Clone, Copy)]
// struct CmsRow {
//     row: [u32; CMS_SIZE as usize],
// }
// #[map]
// static CMS_MAP: Array::<CmsRow> = Array::<CmsRow>::with_max_entries(CMS_ROWS, 0);
// //hash
const CMS_ENTRY_LIMIT: u32 =  131072;
// rows and size updated by userside
// #[no_mangle]
// static CMS_ROWS: u32 = 1;
// #[no_mangle]
// static CMS_SIZE: u32 = 1;
// #[derive(Clone, Copy)]
// struct Cms {
//     row: u32,
//     index: u32
// }
// #[map]
// //(row,index) = value both row and index are user definable, the map can have a max of 1024 rows
// static CMS_MAP: HashMap::<Cms,u32> = HashMap::<Cms,u32>::with_max_entries(CMS_ENTRY_LIMIT, 0);

// #[map]
// //0,numero pacchetti
// static STAT: PerCpuHashMap::<u32,u32> = PerCpuHashMap::<u32,u32>::with_max_entries(1, 0);
fn fasthash(key: &[u8]) -> u32 {
    let mut hash = 2166136261;
    for byte in key {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(16777619);
    }
    hash
}

fn murmurhash3_x86_32(key: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    const R1: u32 = 15;
    const R2: u32 = 13;
    const M: u32 = 5;
    const N: u32 = 0xe6546b64;

    let mut hash = seed;
    let len = key.len();
    let nblocks = len / 4;

    for i in 0..nblocks {
        let mut k: u32 = ((key[i*4] as u32)
            | (key[i*4+1] as u32) << 8
            | (key[i*4+2] as u32) << 16
            | (key[i*4+3] as u32) << 24);

        k = k.wrapping_mul(C1);
        k = k.rotate_left(R1);
        k = k.wrapping_mul(C2);

        hash ^= k;
        hash = hash.rotate_left(R2);
        hash = hash.wrapping_mul(M).wrapping_add(N);
    }

    let tail = &key[nblocks*4..];

    let mut k1: u32 = 0;

    if tail.len() >= 3 { k1 ^= (tail[2] as u32) << 16; }
    if tail.len() >= 2 { k1 ^= (tail[1] as u32) << 8; }
    if tail.len() >= 1 {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(R1);
        k1 = k1.wrapping_mul(C2);
        hash ^= k1;
    }

    hash ^= len as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;
    
    hash
}

fn convert_key_tuple_to_array(key_tuple: (u32, u32, u16, u16, u8)) -> [u8; 13] {
    let mut arr = [0; 13];
    // src IP
    arr[0] = (key_tuple.0 & 0xFF) as u8;
    arr[1] = (key_tuple.0 >> 8 & 0xFF) as u8;
    arr[2] = (key_tuple.0 >> 16 & 0xFF) as u8;
    arr[3] = (key_tuple.0 >> 24 & 0xFF) as u8;
    // dst IP
    arr[4] = (key_tuple.1 & 0xFF) as u8;
    arr[5] = (key_tuple.1 >> 8 & 0xFF) as u8;
    arr[6] = (key_tuple.1 >> 16 & 0xFF) as u8;
    arr[7] = (key_tuple.1 >> 24 & 0xFF) as u8;
    // src port
    arr[8] = (key_tuple.2 & 0xFF) as u8;
    arr[9] = (key_tuple.2 >> 8 & 0xFF) as u8;
    // dst port
    arr[10] = (key_tuple.3  & 0xFF) as u8;
    arr[11] = (key_tuple.3 >> 8 & 0xFF) as u8;
    // proto
    arr[12] = key_tuple.4;
    return arr;
 } 

#[xdp]
pub fn print(ctx: XdpContext) -> u32 {
    match try_print(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}
#[inline(always)] // 
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_print(ctx: XdpContext) -> Result<u32,()> {
    // let inizio = unsafe { bpf_ktime_get_ns() };
    //hash user defined
    let cms_rows = unsafe {core::ptr::read_volatile(&CMS_ROWS)};
    let cms_size = unsafe {core::ptr::read_volatile(&CMS_SIZE)};
    //pointer to the beginning of the ethhdr
    //ctx pointer to the packet
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; 

    //if not ipv4 pass and exit
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    // let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, 0)?;
    let source_addr: u32 = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr: u32 = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let proto : u32 =unsafe {(*ipv4hdr).proto as u32};


    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Err(()),
    };

    let dest_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => return Err(()),
    };

    let key_ip: (u32, u32, u16, u16, u8) = (source_addr,dest_addr,source_port,dest_port,proto as u8);
    let converted_key = convert_key_tuple_to_array(key_ip);
//     info!(&ctx,"{} {} {} {} {} {} {} {} {} {} {} {} {} ",
    
//     converted_key[0],
//     converted_key[1],
//     converted_key[2],
//     converted_key[3],
//     converted_key[4],
//     converted_key[5],
//     converted_key[6],
//     converted_key[7],
//     converted_key[8],
//     converted_key[9],
//     converted_key[10],
//     converted_key[11],
//     converted_key[12]
// );

    let mut hash :u32 = 0;
    let mut index : u32 = 0;
    //hash user defined
    // for i in 0..cms_rows{
    for i in 0..CMS_ROWS{
        if i == 0{
            hash = xxh32(&converted_key,42);
            // hash = fasthash(&converted_key);
            // hash = murmurhash3_x86_32(&converted_key, 33);
        }else {
            //to_ne_bytes converts from u32 to [u8]
            hash = xxh32(&hash.to_ne_bytes(), 42);
            // hash = fasthash(&hash.to_ne_bytes());
            // hash = murmurhash3_x86_32(&hash.to_ne_bytes(), 33);

        }
        //hash user defined
        // index = hash%cms_size;
        index = hash%CMS_SIZE;
        // info!(&ctx,"index {} hash{} cmssyze{} ",index, hash,cms_size);

        // array-one-entry
        if let Some(arr) = CMS_ARRAY.get_ptr_mut(0) {
            unsafe {(*arr).cms[i as usize][index as usize] += 1}
            info!(&ctx, "Row = {} Hash = {} Index = {} Value = {} ", i, hash, index, unsafe{(*arr).cms[i as usize][index as usize]} )
        }else {
            info!(&ctx,"Else cms_array");
        }
        //array-of-rows
        // if let Some(arr) = CMS_MAP.get_ptr_mut(i) {
        //     unsafe {(*arr).row[index as usize] += 1}
        //     info!(&ctx, "Row = {} Hash = {} Index = {} Value = {} ", i, hash, index, unsafe{(*arr).row[index as usize]} )
        // }else {
        //     info!(&ctx,"Else CMS_MAP");
        // }
        //hash
        // let key  = Cms{
        //     row:i,
        //     index:index
        // };
        // if let Some(val)= unsafe { CMS_MAP.get(&key) }{
        //     CMS_MAP.insert(&key, &(*val+1), 0);
        //     info!(&ctx, "Row = {} Hash = {} Index = {} Value = {}", i, hash, index, *val);
            

        // }else {
        //     CMS_MAP.insert(&key, &1, 0);
        // }


    }

    // info!(&ctx, "SRC IP: {:i}, SRC PORT: {}, PROTO: {}, DST IP: {:i}, DST PORT : {}", source_addr, source_port, proto, dest_addr, dest_port);
    // info!(&ctx, "provaaa");
    // info!(&ctx, "provaa2");
    // let fine = unsafe { bpf_ktime_get_ns() };
    // error!(&ctx,"Inizio = {} Fine = {} TEMPO PACCHETTO = {} ns",inizio, fine, fine-inizio);

    // if let Some(val) = unsafe {STAT.get(&0)} {
    //     STAT.insert(&0, &(val+1), 0);

    // }else {
    //     error!(&ctx,"stat non inserito")
    // }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
