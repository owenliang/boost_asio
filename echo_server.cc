#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <exception>
#include <iostream>
#include <string>
#include <deque>
#include <set>
#include "boost/asio.hpp"
#include "boost/thread.hpp"
#include "boost/bind.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/enable_shared_from_this.hpp"
#include "boost/thread/thread.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/atomic.hpp"
#include "boost/program_options/options_description.hpp"
#include "boost/program_options/parsers.hpp"
#include "boost/program_options/variables_map.hpp"
#include "boost/log/common.hpp"
#include "boost/log/core.hpp"
#include "boost/log/sinks.hpp"
#include "boost/log/attributes.hpp"
#include "boost/log/expressions.hpp"
#include "boost/log/trivial.hpp"
#include "boost/log/utility/setup/common_attributes.hpp"
#include "boost/log/utility/exception_handler.hpp"
#include "boost/log/support/date_time.hpp"

namespace {
// ¶¨ÒåÈ«¾ÖÎ¨Ò»µÄsource, Ê¹ÓÃÄÚÖÃµÄseverity_level×÷ÎªÈÕÖ¾¼¶±ğ, Ê¹ÓÃseverity_logger_mtÌá¹©¶àÏß³Ì°²È«
// µÄÈÕÖ¾source.
BOOST_LOG_INLINE_GLOBAL_LOGGER_DEFAULT(global_logger_src, 
    boost::log::sources::severity_logger_mt<boost::log::trivial::severity_level>);

// ¶¨ÒåÊä³öÈÕÖ¾µÄºê, µ÷ÓÃBOOST_LOG_FUNCTIONÀ´Ìá¹©name_scopeÊôĞÔµÄÖµ, ²¢Í¨¹ıBOOST_LOG_SEVÏòÈ«¾ÖsourceÊä³ö´ø¼¶±ğµÄ
// ÈÕÖ¾ĞĞ, ÈÕÖ¾Á÷Ïò: 
// global_logger_src(¹ıÂËÊä³öÈÕÖ¾¼¶±ğ·¶Î§) -> core -> synchronous_sink(frontend,¹ıÂËÌØ¶¨¼¶±ğ) -> text_file_backend
#define LOG(level) BOOST_LOG_FUNCTION();BOOST_LOG_SEV(global_logger_src::get(), boost::log::trivial::level)

boost::shared_ptr<boost::log::sinks::text_file_backend> BuildSinkBackend(const std::string& log_dir, const std::string& sink_name) {
  boost::shared_ptr<boost::log::sinks::text_file_backend> backend = boost::make_shared<boost::log::sinks::text_file_backend>(
        boost::log::keywords::file_name = log_dir + "/echo_server." + sink_name + ".%Y%m%d.%H%M.%N.log",
        boost::log::keywords::rotation_size = 1024ULL * 1024 * 1024,// Ã¿1GBÇĞ»»Ò»¸öÎÄ¼ş
        boost::log::keywords::open_mode = std::ios::app, // ´ò¿ªÎÄ¼ş²ÉÓÃ×·¼ÓĞ´
        boost::log::keywords::auto_flush = true // Ã¿ĞĞÈÕÖ¾Á¢¼´Ë¢µ½´ÅÅÌ
    );
  try {
    backend->set_file_collector(boost::log::sinks::file::make_collector(
          boost::log::keywords::target = log_dir + "/" + sink_name, // ÇĞ»»ºóµÄÈÕÖ¾mvµ½´ËÄ¿Â¼ÏÂ
          boost::log::keywords::max_size = 20ULL * 1024 * 1024 * 1024 // Ä¿Â¼ÏÂÈÕÖ¾×Ü´óĞ¡²»³¬¹ı20GB,·ñÔò»áÌÔÌ­×îÀÏµÄÎÄ¼ş.
          )
        );
    backend->scan_for_files(); // É¨ÃèÄ¿Â¼ÏÂÒÑÓĞÎÄ¼ş,ÒÔ±ãµİÔöÎÄ¼şĞòºÅÒÔ¼°×öÈÕÖ¾ÎÄ¼ş»ØÊÕ.
  } catch (std::exception& except) {
    // ¿ÉÄÜÒòÎªÄ¿Â¼È¨ÏŞÔ­ÒòÊ§°Ü,ÎÒÃÇÖ»´òÓ¡Ò»Ìõ¾¯¸æ²¢¼ÌĞø, Ò»µ©ÓÃ»§»Ö¸´Ä¿Â¼È¨ÏŞ, boost.log»áÁ¢¼´»Ö¸´¹¤×÷.
    std::cerr << except.what() << std::endl; 
  }
  return backend;
}
pid_t gettid() {
  return syscall(SYS_gettid);
}
void InitLogging(bool open_debug, const std::string& log_dir) {
  // »ñÈ¡core, ÒÔ±ãÏòÆä×¢²ásink
  boost::shared_ptr<boost::log::core> core = boost::log::core::get();
  // Ìí¼ÓÍ¨ÓÃÊôĞÔ(Ê±¼ä,½ø³ÌID,Ïß³ÌID)
  // ×¢: boost::log::add_common_attributes();º¯ÊıÌí¼ÓµÄ½ø³ÌIDºÍÏß³ÌIDÊÇ16½øÖÆµÄ,ÎÒ¾ö¶¨×Ô¶¨Òålinux¶©ÖÆµÄ°æ±¾.
  core->add_global_attribute("TimeStamp", boost::log::attributes::local_clock());
  core->add_global_attribute("ProcessID", boost::log::attributes::make_function(&getpid));
  core->add_global_attribute("ThreadID", boost::log::attributes::make_function(&gettid));
  // Ìí¼Ó×÷ÓÃÓòÊôĞÔ£¨º¯ÊıÃû,Ô´ÎÄ¼şÃû,ĞĞºÅ)
  core->add_global_attribute("Scope", boost::log::attributes::named_scope());
  // ºöÂÔËùÓĞlog¿â¿ÉÄÜÅ×³öµÄÒì³£
  core->set_exception_handler(boost::log::make_exception_suppressor());
  // ¹Ø±Õµ÷ÊÔÈÕÖ¾
  if (!open_debug) {
    core->set_filter(boost::log::expressions::attr<boost::log::trivial::severity_level>("Severity") >= boost::log::trivial::info);
  }
  typedef boost::log::sinks::synchronous_sink<boost::log::sinks::text_file_backend> sync_sink_frontend;
  // ¹¹Ôì3¸ösink:
  // 1,severity<=debug¼¶±ğµÄÊä³öµ½sink_trace_debug
  boost::log::formatter scope_formatter = boost::log::expressions::stream << "[" <<
          boost::log::expressions::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S") <<
          "] [" << boost::log::expressions::attr<pid_t>("ProcessID") << "-" << boost::log::expressions::attr<pid_t>("ThreadID") << 
          "] [" << boost::log::expressions::attr<boost::log::trivial::severity_level>("Severity") <<
          "] " << boost::log::expressions::format_named_scope("Scope", boost::log::keywords::format = "%c[%F:%l] ", 
          boost::log::keywords::depth = 1) << boost::log::expressions::smessage;
  boost::shared_ptr<boost::log::sinks::text_file_backend> sink_trace_debug_backend = BuildSinkBackend(log_dir, "trace_debug");
  boost::shared_ptr<sync_sink_frontend> sink_trace_debug_frontend(new sync_sink_frontend(sink_trace_debug_backend));
  sink_trace_debug_frontend->set_filter(
      boost::log::expressions::attr<boost::log::trivial::severity_level>("Severity") <= boost::log::trivial::debug && 
      boost::log::expressions::attr<boost::log::trivial::severity_level>("Severity") >= boost::log::trivial::trace);
  sink_trace_debug_frontend->set_formatter(scope_formatter);
  core->add_sink(sink_trace_debug_frontend);
  // 2,debug<severity<=warning¼¶±ğµ½sink_info_warning
  boost::log::formatter non_scope_formatter = boost::log::expressions::stream << "[" <<
          boost::log::expressions::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S") <<
          "] [" << boost::log::expressions::attr<pid_t>("ProcessID") << "-" << boost::log::expressions::attr<pid_t>("ThreadID") << 
          "] [" << boost::log::expressions::attr<boost::log::trivial::severity_level>("Severity") << 
          "] " << boost::log::expressions::smessage;
  boost::shared_ptr<boost::log::sinks::text_file_backend> sink_info_warning_backend = BuildSinkBackend(log_dir, "info_warning");
  boost::shared_ptr<sync_sink_frontend> sink_info_warning_frontend(new sync_sink_frontend(sink_info_warning_backend));
  sink_info_warning_frontend->set_filter(
      boost::log::expressions::attr<boost::log::trivial::severity_level>("Severity") <= boost::log::trivial::warning && 
      boost::log::expressions::attr<boost::log::trivial::severity_level>("Severity") > boost::log::trivial::debug);
  sink_info_warning_frontend->set_formatter(non_scope_formatter);
  core->add_sink(sink_info_warning_frontend);
  // 3,warning<severity<=fatal¼¶±ğÊä³öµ½sink_error_fatal
  boost::shared_ptr<boost::log::sinks::text_file_backend> sink_error_fatal_backend = BuildSinkBackend(log_dir, "error_fatal");
  boost::shared_ptr<sync_sink_frontend> sink_error_fatal_frontend(new sync_sink_frontend(sink_info_warning_backend));
  sink_error_fatal_frontend->set_filter(
      boost::log::expressions::attr<boost::log::trivial::severity_level>("Severity") <= boost::log::trivial::fatal &&
      boost::log::expressions::attr<boost::log::trivial::severity_level>("Severity") > boost::log::trivial::warning);
  sink_error_fatal_frontend->set_formatter(non_scope_formatter);
  core->add_sink(sink_error_fatal_frontend);
}

class EchoServer;

typedef boost::shared_ptr<EchoServer> EchoServerPtr;
typedef boost::shared_ptr<boost::asio::io_service> IOServicePtr;
typedef boost::shared_ptr<boost::asio::ip::tcp::socket> SocketPtr;
class Connection;
typedef boost::shared_ptr<Connection> ConnPtr;
typedef boost::shared_ptr<std::string> StringPtr;
typedef boost::shared_ptr<boost::asio::deadline_timer> TimerPtr;

// ×¼Ôò1:
// Ò»¸öSocketÓÀÔ¶²»Òªµ÷ÓÃasync_read/async_write³¬¹ı1´Î,¿ÉÒÔ²Î¿¼boost doc:
// This operation is implemented in terms of zero or more calls to the stream's async_write_some function, and is known as a composed operation. The program must ensure that the stream performs no other write operations (such as async_write, the stream's async_write_some function, or any other composed operations that perform writes) until this operation completes.
// Ò²¾ÍÊÇÒ»¶¨ÒªÇ°Ò»¸öasync²Ù×÷Íê³ÉÔÙ·¢ÆğÏÂÒ»¸ö!!

// ×¼Ôò2:
// ²Ù×÷1¸ösocket, ÔÚ¶àÏß³ÌÌõ¼şÏÂÒ»¶¨Òª¼ÓËø´¦Àí, Ò»°Ñ´óËø½â¾öÒ»ÇĞÎÊÌâ, ÆäËûÓÃ·¨¶¼ÊÇ·ÇÏß³Ì°²È«µÄ.
// Ò²¾ÍÊÇËµÍ¬²½close/async_read/async_write/async_connectÕâËÄ¸öº¯Êıµ÷ÓÃ¼´¿É.

class Connection : public boost::enable_shared_from_this<Connection> {
public:
  enum ConnStatus {
    kConnected = 0,
    kError = 1,
    kClosed = 2,
  };
  Connection(SocketPtr socket) : status_(kConnected), socket_(socket) {
  }
  ~Connection() {
    // ¿ÉÒÔÔÚÕâÀï½«write_queueÖĞµÄ´ı·¢ÏûÏ¢½øĞĞÖØÊÔµÈÂß¼­´¦Àí
    LOG(debug) << __FUNCTION__;
  }
  void Start() { 
    socket_->async_receive(boost::asio::buffer(msgbuf_, sizeof(msgbuf_)), boost::bind(&Connection::ReadHandler, shared_from_this(), _1, _2));
  }
  void Close() { // ÖØ¸´µÄµ÷ÓÃsocketµÄcloseÃ»ÓĞÎÊÌâ, µ«²»ÄÜ²¢·¢µ÷ÓÃclose(¼ÙÉèClose½Ó¿Ú±©Â¶¸øÓÃ»§,ÊÇÓĞÕâÖÖĞèÇóµÄ).
    if (status_.exchange(kClosed) != kClosed) { // ¼´±ãÖØ¸´µ÷ÓÃsocketµÄcloseÊÇÃ»ÓĞÎÊÌâµÄ, µ«ÊÇÕâÀïÒ²±£Ö¤CloseÖ»ÄÜ±»÷ÓÃÒ»´Î.
      boost::lock_guard<boost::mutex> guard(socket_mutex_);
      boost::system::error_code errcode;
      if (socket_->close(errcode)) {
        LOG(warning) << "Close Connection Error";
      } else {
        LOG(info) << "Close Connection Done";
      }
    }
  }
  ConnStatus status() { return status_.load(); }
private:
  void ReadHandler(const boost::system::error_code& error, std::size_t bytes_transferred) {
    if (!error) { // Ã»ÓĞ·¢Éú´íÎó(°üº¬±»È¡Ïû), ÄÇÃ´·¢ÆğÏÂÒ»´Î¶ÁÈ¡.
      // ¸Ãº¯Êı¶Áµ½Ò»Ğ©Êı¾İ¾Í»á·µ»Ø, ÕıºÃÊÊÓÃÓÚÕâÀïµÄechoÂß¼­. Èç¹ûÏ£Íû¶ÁÈ¡Ö¸¶¨³¤¶ÈÍê³ÉÇ°²»·µ»Ø, Ê¹ÓÃasync_read.
      {
        boost::lock_guard<boost::mutex> guard(socket_mutex_);
        socket_->async_receive(boost::asio::buffer(msgbuf_, sizeof(msgbuf_)), boost::bind(&Connection::ReadHandler, shared_from_this(), _1, _2));
      }
      // ÕâÀïÕ¹Ê¾Ò»ÏÂÈçºÎÔÚ¶àÏß³ÌasioÏÂÕıÈ·µÄÊ¹ÓÃasync_writeÓĞĞòµÄ·¢ËÍecho, ²¢ÇÒ´ı·¢ËÍÏûÏ¢¶ÓÁĞÒÔ±ãÔÚsocketÊ§Ğ§Ê±ÓĞ»ú»á·¢ËÍÏûÏ¢ÖØ·¢.
      EchoMsg(StringPtr(new std::string(msgbuf_, bytes_transferred)));
    } else if (error == boost::asio::error::operation_aborted) {
      LOG(trace) << "Connection ReadHandler Canceled.";
    } else {
      ConnStatus expected = kConnected;
      if (status_.compare_exchange_strong(expected, kError)) {
        LOG(warning) << "ReadHandler Error.";
      }
    }
  }
  void WriteHandler(const boost::system::error_code& error, std::size_t bytes_transferred) {
    if (!error) {
      boost::lock_guard<boost::mutex> guard(socket_mutex_);
      write_queue_.pop_front();
      if (write_queue_.size()) {
        StringPtr next_msg = write_queue_.front();
        // async_write±£Ö¤Êı¾İÈ«²¿Ğ´Íê»Øµ÷.
        async_write(*socket_, boost::asio::buffer(*next_msg), boost::bind(&Connection::WriteHandler, shared_from_this(), _1, _2));
      }
    } else if (error == boost::asio::error::operation_aborted) {
      LOG(trace) << "Connection WriteHandler Canceled.";
    } else {
      ConnStatus expected = kConnected;
      if (status_.compare_exchange_strong(expected, kError)) {
        LOG(warning) << "WriteHandler Error.";
      }
    }
  }
  void EchoMsg(StringPtr msg) {
    LOG(debug) << "EchoMsg: " << *msg;
    boost::lock_guard<boost::mutex> guard(socket_mutex_);
    write_queue_.push_back(msg);
    if (write_queue_.size() == 1) {
      async_write(*socket_, boost::asio::buffer(*msg), boost::bind(&Connection::WriteHandler, shared_from_this(), _1, _2));
    }
  }
  std::deque<StringPtr> write_queue_;
  boost::mutex socket_mutex_;
  boost::atomic<ConnStatus> status_;
  char msgbuf_[1024 * 16];
  SocketPtr socket_;
};

class EchoServer : public boost::enable_shared_from_this<EchoServer> {
public:
  EchoServer(IOServicePtr io_service) : stopped_(false), io_service_(io_service), acceptor_(*io_service) {
  }
  ~EchoServer() {
    // ÔÚStopºóÖ÷Ïß³ÌÊÍ·ÅÒıÓÃ¼ÆÊı, µÈ´ıio_service´¦ÀíÍêÊ£ÓàÊÂ¼şºóÎö¹¹, ´ËÊ±²»»áÔÙÓĞĞÂÁ¬½Ó¼ÓÈë,
    // ¿ÉÒÔCloseµôËùÓĞSocket²¢ÊÍ·ÅÒıÓÃ¼ÆÊı.
    LOG(trace) << __FUNCTION__;
    boost::lock_guard<boost::mutex> guard(conn_set_mutex_);
    for (ConnSetIter iter = conn_set_.begin(); iter != conn_set_.end(); ++iter) {
      (*iter)->Close();
    }
  }
  bool Start(const std::string& host, unsigned short port) {
    boost::system::error_code errcode;
    boost::asio::ip::address address = boost::asio::ip::address::from_string(host, errcode);
    if (errcode) {
      return false;
    }
    if (acceptor_.open(boost::asio::ip::tcp::v4(), errcode)) {
      return false;
    }
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    boost::asio::ip::tcp::endpoint endpoint(address, port);
    if (acceptor_.bind(endpoint, errcode) || acceptor_.listen(1024, errcode)) {
      acceptor_.close();
      return false;
    }
    SocketPtr socket(new boost::asio::ip::tcp::socket(*io_service_));
    acceptor_.async_accept(*socket, boost::bind(&EchoServer::AcceptHandler, shared_from_this(), socket, _1));
    return true;
  }
  void Stop() {
    boost::lock_guard<boost::mutex> guard(socket_mutex_);
    boost::system::error_code errcode;
    if (acceptor_.close(errcode)) {
      LOG(warning) << "Close Acceptor Error";
    }
    stopped_.store(true);
  }
private:
  void AcceptHandler(SocketPtr socket, const boost::system::error_code& error) { // Ã»ÓĞ²¢·¢µ÷ÓÃ
    if (error == boost::asio::error::operation_aborted) { // ÒòAcceptor±»¹Ø±Õ¶øCancel, ²»ĞèÒª×öÈÎºÎÊÂÇé.
      LOG(trace) << "Accept Canceled";
      return; // ÓÃ»§Ö÷¶¯¹Ø±ÕÁËServer, Òò´Ë²Ù×÷±»Cancel
    } else if (!error) { // ³É¹¦Accept, ´´½¨Ò»¸öĞÂµÄConnection.
      LOG(info) << "Accept New Connection";
      ConnPtr new_conn(new Connection(socket));
      new_conn->Start();
      {
        boost::lock_guard<boost::mutex> guard(conn_set_mutex_);
        conn_set_.insert(new_conn);
      }
      TimerPtr socket_timer(new boost::asio::deadline_timer(*io_service_));
      socket_timer->expires_from_now(boost::posix_time::seconds(1));
      socket_timer->async_wait(boost::bind(&EchoServer::CheckSocketStatus, shared_from_this(), new_conn, socket_timer, _1));
    } else {
      LOG(error) << "Accept Error";
    }
    SocketPtr new_socket(new boost::asio::ip::tcp::socket(*io_service_));
    boost::lock_guard<boost::mutex> guard(socket_mutex_);
    acceptor_.async_accept(*new_socket, boost::bind(&EchoServer::AcceptHandler, shared_from_this(), new_socket, _1));
  }
  void CheckSocketStatus(ConnPtr conn, TimerPtr socket_timer, const boost::system::error_code& error) {
    // 1, EchoServerÒÑ¾­±»Stopµ÷ÓÃ, ÄÇÃ´¾¡¿ìÍ£Ö¹timerÊÍ·Åµô¶ÔEchoServerµÄÒıÓÃ¼ÆÊı, ÈÃEchoServerÎö¹¹½áÊø·şÎñ¡£
    // 2, ÅĞ¶Ïconn->status()==kErrorÔòCloseÁ¬½Ó²¢´ÓConnSetÖĞÒÆ³ı.
    // 3, ÅĞ¶Ïconn->status()==kClosedÔò´ÓConnSetÖĞÒÆ³ı.(½«À´ÓÃ»§¿ÉÒÔ»ñÈ¡SocketPtr²¢ËæÊ±µ÷ÓÃClose)
    // 4, Á¬½ÓÕı³£, ¼ÌĞø·¢ÆğÏÂÒ»´Îtimer.
    boost::lock_guard<boost::mutex> guard(conn_set_mutex_);
    ConnSetIter iter = conn_set_.find(conn);
    assert(iter != conn_set_.end());
    if (stopped_.load()) {
      // case 1
      //LOG(debug) << "case 1";
    } else if (conn->status() == Connection::kError) { // case 2
      //LOG(debug) << "case 2";
      conn->Close();
      conn_set_.erase(conn);
    } else if (conn->status() == Connection::kClosed) {// case 3
      //LOG(debug) << "case 3";
      conn_set_.erase(conn);
    } else {
      //LOG(debug) << "case 4"; // case 4
      socket_timer->expires_from_now(boost::posix_time::seconds(1));
      socket_timer->async_wait(boost::bind(&EchoServer::CheckSocketStatus, shared_from_this(), conn, socket_timer, _1));
    }
  }
  typedef std::set<ConnPtr> ConnSet;
  typedef ConnSet::iterator ConnSetIter;
  boost::atomic<bool> stopped_;
  boost::mutex socket_mutex_;
  boost::mutex conn_set_mutex_;
  ConnSet conn_set_;
  IOServicePtr io_service_;
  boost::asio::ip::tcp::acceptor acceptor_; // auto-close while destructor.
};
volatile sig_atomic_t g_shutdown_server = 0;
void ShutdownServerHandler(int signo) {
  g_shutdown_server = 1;
}
void SetupSignalHandler() {
  sigset_t sigset;
  sigfillset(&sigset);
  sigdelset(&sigset, SIGTERM);
  sigdelset(&sigset, SIGINT);
  sigprocmask(SIG_SETMASK, &sigset, NULL);

  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = ShutdownServerHandler;
  sigaction(SIGINT, &act, NULL);
  sigaction(SIGTERM, &act, NULL);
}
void AsioThreadMain(IOServicePtr io_service) {
  // ¶àÏß³Ìµ÷ÓÃÕâ¸öio_serviceÅÜleader-followerÄ£ĞÍ
  // ³õÊ¼»¯¹ÒÁËÒ»¸öEchoServerµÄAcceptorÔÚÀïÃæ, Ö÷Ïß³Ìµ÷ÓÃStop²¢ResetÊÍ·ÅÒıÓÃºó,
  // io_service»á´¦ÀíÍêacceptorÊ£ÓàÊÂ¼şºóÊÍ·ÅÒıÓÃ¼ÆÊı´Ó¶øÊ¹echoserverÎö¹¹, ÔÚechoserverÎö¹¹ÖĞ
  // »á½«ËùÓĞÔÚÏßµÄsocket½øĞĞclose²¢ÊÍ·ÅÒıÓÃ¼ÆÊı, µÈio_service´¦ÀíÍêËùÓĞsocketµÄÊ£ÓàÊÂ¼şºóÊÍ·ÅÒıÓÃ¼ÆÊı
  // ´Ó¶øÊ¹ËùÓĞsocketÎö¹¹, ×îÖÕio_serviceÉÏ½«ÎŞÈÎºÎÊÂ¼ş, ×Ô¶¯ÍË³öÏß³Ì.
  io_service->run();
}
bool ParseCommands(int argc, char** argv, boost::program_options::variables_map* options) {
  boost::program_options::options_description desc("Usage");
  desc.add_options()
      ("help", "show how to use this program")
      ("thread,t", boost::program_options::value<uint32_t>()->default_value(12), "number of threads of asio")
      ("port,p", boost::program_options::value<unsigned short>()->required(), "the tcp port server binds to")
      ("config,c", boost::program_options::value<std::string>(), "read config from file")
      ("log,l", boost::program_options::value<std::string>()->default_value("./serverlog"), "the directory to write log")
      ("debug,d", "open debug mode for logging");
  try {
    // ÓÅÏÈÃüÁîĞĞ
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), *options); 
    if (options->count("help")) { 
      std::cerr << desc << std::endl;
      return false;
    }
    if (options->count("config")) { // ÅäÖÃÎÄ¼ş×÷Îª²¹³ä
      std::string cfile = (*options)["config"].as<std::string>();
      boost::program_options::store(boost::program_options::parse_config_file<char>(cfile.c_str(), desc), *options);
    }
    boost::program_options::notify(*options); // ×îÖÕ´¥·¢²ÎÊıĞ£Ñé
  } catch (std::exception& except) {
    std::cerr << except.what() << std::endl;
    std::cerr << desc << std::endl;
    return false;
  }
  return true;
}
}

int main(int argc, char** argv) {
  boost::program_options::variables_map options;
  if (!ParseCommands(argc, argv, &options)) {
    return -1;
  }
  InitLogging(options.count("debug"), options["log"].as<std::string>());
  
  SetupSignalHandler();

  IOServicePtr io_service(new boost::asio::io_service());

  unsigned short port = options["port"].as<unsigned short>();

  EchoServerPtr echo_server(new EchoServer(io_service));
  if (!echo_server->Start("0.0.0.0", port)) {
    return -1;
  }
  uint32_t thread_num = options["thread"].as<uint32_t>();
  boost::thread_group asio_threads;
  for (uint32_t i = 0; i < thread_num; ++i) {
    asio_threads.create_thread(boost::bind(AsioThreadMain, io_service));
  }

  while (!g_shutdown_server) {
    sleep(1);
  }
  echo_server->Stop(); // ¹Ø±Õ¼àÌıÆ÷
  echo_server.reset();   // ÊÍ·ÅÒıÓÃ¼ÆÊı, ÈÃecho_serverÎö¹¹.
  asio_threads.join_all(); // µÈ´ıasio×ÔÈ»ÍË³ö
  LOG(info) << "Stopped.. ..";
  return 0;
}
