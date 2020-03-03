#include <mach/mach_types.h>
#include <sys/kernel_types.h>
#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
#include <i386/endian.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/kpi_ipfilter.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/kern_event.h>
#include <libkern/libkern.h>
#include <IOKit/IOLib.h>
#include "sha-256.h"
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <libkern/OSByteOrder.h>
#include <kern/assert.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/malloc.h>
#include <UserNotification/KUNCUserNotifications.h>



#include <stdint.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/kauth.h>
#include <kern/debug.h>
#include <sys/disk.h>
#include <vm/vm_pageout.h>





//WORKIMG


kern_return_t FilterKit_start (kmod_info_t * ki, void * d);
kern_return_t FilterKit_stop (kmod_info_t * ki, void * d);

//kauth callback
// ->for KAUTH_FILEOP_EXEC events, broadcast process notifications to user-mode
static int processExec(kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

/* GLOBALS */

//kauth listener
// ->scope KAUTH_SCOPE_FILEOP
kauth_listener_t kauthListener = NULL;

//kext's/objective-see's vendor id
u_int32_t objSeeVendorID = 0;
enum {
    kMyFiltDirIn,
    kMyFiltDirOut,
    kMyFiltNumDirs
};

struct myfilter_stats
{
    unsigned long udp_packets[kMyFiltNumDirs];
    unsigned long tcp_packets[kMyFiltNumDirs];
    unsigned long icmp_packets[kMyFiltNumDirs];
    unsigned long other_packets[kMyFiltNumDirs];
};

/// HASHING

static void hash_to_string(char string[65], const uint8_t hash[32])
{
    size_t i;
    for (i = 0; i < 32; i++) {
        string += sprintf(string, "%02x", hash[i]);
    }
}

/// END HASHING

static struct myfilter_stats g_filter_stats;
static ipfilter_t g_filter_ref;
static boolean_t g_filter_registered = FALSE;
static boolean_t g_filter_detached = FALSE;

void filehash(void* path, int pid, int ppid, int uid)
{
    struct vnode *vp = NULL;
    kern_return_t kret;
    vfs_context_t ctx = vfs_context_create(NULL);
    
    kret = vnode_open(path, FREAD, 0, 0, &vp, ctx);
    if (kret != KERN_SUCCESS) {
        //kprintf("NOPE - FAIL - %s",path);
        return;
    } else {
        proc_t proc = vfs_context_proc(ctx);
        kauth_cred_t vp_cred = vfs_context_ucred(ctx);
        
        int fserror = 1;
        long my_file_size = 0;
        struct vnode_attr va;
        VATTR_INIT(&va);
        VATTR_WANTED(&va, va_data_size);
        fserror = vnode_getattr(vp, &va, ctx);
        if (!fserror && VATTR_IS_SUPPORTED(&va, va_data_size))
            my_file_size = va.va_data_size;
        
        char *buf = NULL;
        int resid;
        buf = (char *)IOMalloc(my_file_size);
        
        kret = vn_rdwr(UIO_READ, vp, (caddr_t)buf, my_file_size, 0, UIO_SYSSPACE, 0, vp_cred, &resid, proc);
        
        vnode_close(vp, FREAD, ctx);
        
        if (kret != KERN_SUCCESS) {
            //kprintf("NOPE - FAIL");
            return;
        }
        
        //kprintf("NOPE - YEA - %i",path,kret);
        uint8_t hash[32];
        char hash_string[65];
        calc_sha_256(hash, buf, my_file_size);
        hash_to_string(hash_string, hash);
        kprintf("NOPE - NEWPROCESS - PATH: %s - PID: %d - PPID: %d - UID: %d - HASH: %s",path,pid,ppid,uid,hash_string);
    }
    vfs_context_rele(ctx);
    
    return;
}


//kauth callback
// ->for KAUTH_FILEOP_EXEC events, broadcast process notifications to user-mode
static int processExec(kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    
    //path
    char path[MAXPATHLEN+1] = {0};
    
    //uid
    uid_t uid = -1;
    
    //pid
    pid_t pid = -1;
    
    //ppid
    pid_t ppid = -1;
    
    
    //ignore all non exec events
    if(KAUTH_FILEOP_EXEC != action)
    {
        //bail
        goto bail;
    }
    
    //zero out path
    bzero(&path, sizeof(path));
    
    //path is arg1 (per sys/k_auth.h)
    // ->make copy, so broadcast to usermode works
    strncpy(path, (const char*)arg1, MAXPATHLEN);
    
    //get UID
    uid = kauth_getuid();
    
    //get pid
    pid = proc_selfpid();
    
    //get ppid
    ppid = proc_selfppid();
    
    char hash_string[65];
    
    
    filehash(path,pid,ppid,uid);
    
    //dbg msg
    //printf ("NOPE: new process: path: %s pid: %d ppid: %d uid: - %d\n", path, pid, ppid, uid);
    
    //new thread to calc hash




        //printf ("NOPE - END OF CALLING PROCESS - %s",path);
    goto bail;
    
    
    //bail
bail:
    
    return KAUTH_RESULT_DEFER;
    
}



static void log_ip_packet(mbuf_t *data, int dir)
{
    char src[32], dst[32];
    struct ip *ip = (struct ip*)mbuf_data(*data);
    int pid;
    int uid;
    int ppid;

    
    if (ip->ip_v != 4)
        return;
    
    bzero(src, sizeof(src));
    bzero(dst, sizeof(dst));
    inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));
    
    char name[PATH_MAX];
    proc_selfname(name, PATH_MAX);
    uid = kauth_getuid();
    pid = proc_selfpid();
    ppid = proc_selfppid();
    
    
    switch (ip->ip_p) {
        case IPPROTO_TCP:

            kprintf("NOPE - TCP: - %s  - UID: %d - PID: %d - PPID: %d - SRC: %s DST: %s\n", name, uid, pid, ppid, src, dst);
            g_filter_stats.tcp_packets[dir]++;
            break;
        case IPPROTO_UDP:
            kprintf("NOPE - UDP: - %s  - UID: %d - PID: %d - PPID: %d - SRC: %s DST: %s\n", name, uid, pid, ppid, src, dst);
            g_filter_stats.udp_packets[dir]++;
            break;
        case IPPROTO_ICMP:
            kprintf("NOPE - ICMP: - %s  - UID: %d - PID: %d - PPID: %d - SRC: %s DST: %s\n", name, uid, pid, ppid, src, dst);
            g_filter_stats.icmp_packets[dir]++;
        default:
            kprintf("NOPE - OTHER: - %s  - UID: %d - PID: %d - PPID: %d - SRC: %s DST: %s\n", name, uid, pid, ppid, src, dst);
            g_filter_stats.other_packets[dir]++;
            break;
    }

}


static errno_t filterkit_output(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
    if (data)
        log_ip_packet(data, kMyFiltDirOut);
    //return filterkit_output_redirect(cookie, data, options);
    return 0;
}

static errno_t filterkit_input(void *cookie, mbuf_t *data, int offset, u_int8_t protocol)
{
    if (data)
        log_ip_packet(data, kMyFiltDirIn);
    //return filterkit_input_redirect(cookie, data, offset, protocol);
    return 0;
}

static void filterkit_detach(void *cookie)
{
    /* cookie isn't dynamically allocated, no need to free in this case */
    struct myfilter_stats* stats = (struct myfilter_stats*)cookie;
    printf("UDP_IN %lu UDP OUT: %lu TCP_IN: %lu TCP_OUT: %lu ICMP_IN: %lu ICMP OUT: %lu OTHER_IN: %lu OTHER_OUT: %lu\n",
           stats->udp_packets[kMyFiltDirIn],
           stats->udp_packets[kMyFiltDirOut],
           stats->tcp_packets[kMyFiltDirIn],
           stats->tcp_packets[kMyFiltDirOut],
           stats->icmp_packets[kMyFiltDirIn],
           stats->icmp_packets[kMyFiltDirOut],
           stats->other_packets[kMyFiltDirIn],
           stats->other_packets[kMyFiltDirOut]);
    
    g_filter_detached = TRUE;
    
}

static struct ipf_filter g_my_ip_filter = {
    &g_filter_stats,
    "com.osxkernel.FilterKit",
    filterkit_input,
    filterkit_output,
    filterkit_detach
};

kern_return_t FilterKit_start (kmod_info_t * ki, void * d) {
    
    int result;
    
    bzero(&g_filter_stats, sizeof(struct myfilter_stats));
    
    result = ipf_addv4(&g_my_ip_filter, &g_filter_ref);
    
    int x = 0;
    
    if (result == KERN_SUCCESS)
        x = 1;
    
    kauthListener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, &processExec, NULL);
    
    if(NULL != kauthListener)
        x = 2;
    
    if (x == 2)
        g_filter_registered = TRUE;
    
    return result;
}

kern_return_t FilterKit_stop (kmod_info_t * ki, void * d) {


    if (g_filter_registered)
    {
        ipf_remove(g_filter_ref);
        g_filter_registered = FALSE;
    }
    if(NULL != kauthListener)
    {
        //unregister
        kauth_unlisten_scope(kauthListener);
        
        //unset
        kauthListener = NULL;
    }
    
    
    /* We need to ensure filter is detached before we return */
    if (!g_filter_detached)
        return EAGAIN; // Try unloading again.
    
    return KERN_SUCCESS;
}
