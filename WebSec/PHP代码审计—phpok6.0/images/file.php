<?php
/**
 * 文件操作类
 * @作者 qinggan <admin@phpok.com>
 * @版权 2015-2016 深圳市锟铻科技有限公司
 * @主页 http://www.phpok.com
 * @版本 4.x
 * @授权 http://www.phpok.com/lgpl.html PHPOK开源授权协议：GNU Lesser General Public License
 * @时间 2016年12月08日
**/

class file_lib
{
	public $read_count;
	private $safecode = "<?php die('forbidden'); ?>\n";
	public function __construct()
	{
		$this->read_count = 0;
	}

	/**
	 * 远程获取内容，这里直接调用html类来执行
	 * @参数 $url 网址
	 * @参数 $post 要提交的post数据
	**/
	public function remote($url,$post='')
	{
		return $GLOBALS['app']->lib('html')->get_content($url,$post);
	}

	/**
	 * 读取数据
	 * @参数 $file 要读取的文件，支持远程文件
	 * @参数 $length 文件长度，为空表示读取全部，仅限本地文件有效
	 * @参数 $filter 是否过滤安全字符，默认为true，不过滤请传参false，仅限本地文件有效
	 * @返回 false 或 文件内容
	**/
	public function cat($file="",$length=0,$filter=true)
	{
		if(!$file){
			return false;
		}
		if(strpos($file,"://") !== false && strpos($file,'file://') === false){
			return $this->remote($file);
		}
		if(!file_exists($file)){
			return false;
		}
		$this->read_count++;
		
		if($length && is_numeric($length)){
			$maxlength = $length;
			if($filter){
				$maxlength = $length + strlen($this->safecode);
			}
			$fp = fopen($file,'rb');
			if(!$fp){
				return false;
			}
			$content = fread($fp,$maxlength);
			fclose($fp);
		}else{
			$content = file_get_contents($file);
		}
		if(!$content){
			return false;
		}
		if($filter || (is_bool($length) && $length)){
			$content = str_replace($this->safecode,'',$content);
		}
		return $content;
	}

	/**
	 * 保存数据
	 * @参数 $content 要保存的内容，支持字符串，数组，多维数组等
	 * @参数 $file 保存的文件地址
	 * @参数 $var 仅限$content为数组，此项不为空时使用
	 * @参数 $type 写入方式，默认为wb，清零写入
	 * @返回 true/false
	**/
	public function vi($content='',$file='',$var="",$type="wb")
	{
		if(!$content || !$file){
			return false;
		}
		$this->make($file,"file");
		if(is_array($content) && $var){
			$content = $this->__array($content,$var);
			$safecode = 'if(!defined("PHPOK_SET")){exit("<h1>Access Denied</h1>");}';
			$content = "<?php\n".$safecode."\n".$content."\n//-----end";
		}else{
			if(strtolower($type) == 'wb' || strtolower($type) == 'w'){
				$content = $this->safecode.$content;
			}
		}
		$this->_write($content,$file,$type);
		return true;
	}

	/**
	 * 存储php等源码文件，不会写入安全保护
	 * @参数 $content 要保存的内容
	 * @参数 $file 保存的地址
	 * @参数 $type 写入模式，wb 表示完全写入，ab 表示追加写入
	**/
	public function vim($content,$file,$type="wb")
	{
		$this->make($file,"file");
		return $this->_write($content,$file,$type);
	}

	/**
	 * 保存数据别名，不改写任何东西
	 * @参数 $content 要保存的内容
	 * @参数 $file 保存的地址
	 * @参数 $type 写入模式，wb 表示完全写入，ab 表示追加写入
	**/
	public function save($content,$file,$type='wb')
	{
		return $this->vim($content,$file,$type);
	}

	/**
	 * 存储图片，内容不进行stripslashes处理
	 * @参数 $content 要保存的内容
	 * @参数 $file 要保存的文件
	 * @返回 
	 * @更新时间 
	**/
	public function save_pic($content,$file)
	{
		$this->make($file,"file");
		$handle = $this->_open($file,"wb");
		fwrite($handle,$content);
		unset($content);
		$this->_close($handle);
		return true;
	}

	/**
	 * 删除操作，请一定要小心，在程序中最好严格一些，不然有可能将整个目录删掉
	 * @参数 $del 要删除的文件或文件夹
	 * @参数 $type 仅支持file和folder，为file时仅删除$del文件，如果$del为文件夹，表示删除其下面的文件。为folder时，表示删除$del这个文件，如果为文件夹，表示删除此文件夹及子项
	 * @返回 true/false
	**/
	public function rm($del,$type="file")
	{
		if(!file_exists($del)){
			return false;
		}
		if(is_file($del)){
			unlink($del);
			return true;
		}
		$array = $this->_dir_list($del);
		if(!$array){
			if($type == 'folder'){
				rmdir($del);
			}
			return true;
		}
		foreach($array as $key=>$value){
			if(file_exists($value)){
				if(is_dir($value)){
					$this->rm($value,$type);
				}else{
					unlink($value);
				}
			}
		}
		if($type == "folder"){
			rmdir($del);
		}
		return true;
	}

	/**
	 * 创建文件或目录
	 * @参数 $file 文件或目录
	 * @参数 $type 默认是dir，表示创建目录
	 * @返回 true
	**/
	public function make($file,$type="dir")
	{
		$newfile = $file;
		$msg = "";
		if(defined("ROOT")){
			$root_strlen = strlen(ROOT);
			if(substr($file,0,$root_strlen) == ROOT){
				$newfile = substr($file,$root_strlen);
			}
			$msg = ROOT;//从根目录记算起是否有文件写入
		}
		$array = explode("/",$newfile);
		$count = count($array);
		if($type == "dir"){
			for($i=0;$i<$count;$i++){
				$msg .= $array[$i];
				if(!file_exists($msg) && ($array[$i])){
					mkdir($msg,0777);
				}
				$msg .= "/";
			}
		}else{
			for($i=0;$i<($count-1);$i++){
				$msg .= $array[$i];
				if(!file_exists($msg) && ($array[$i])){
					mkdir($msg,0777);
				}
				$msg .= "/";
			}
			if(!file_exists($file)){
				@touch($file);//创建文件
			}
		}
		return true;
	}

	/**
	 * 复制操作
	 * @参数 $old 旧文件（夹）
	 * @参数 $new 新文件（夹）
	 * @参数 $recover 是否覆盖
	 * @返回 false/true
	**/
	public function cp($old,$new,$recover=true)
	{
		if(!file_exists($old)){
			return false;
		}
		if(is_file($old)){
			//如果目标是文件夹
			if(substr($new,-1) == '/'){
				$this->make($new,'dir');
				$basename = basename($old);
				if(file_exists($new.$basename) && !$recover){
					return false;
				}
				copy($old,$new.$basename);
				return true;
			}
			if(file_exists($new) && !$recover){
				return false;
			}
			copy($old,$new);
			return true;
		}
		$basename = basename($old);
		$this->make($new.$basename,'dir');
		$dlist = $this->ls($old);
		if($dlist && count($dlist)>0){
			foreach($dlist as $key=>$value){
				$this->cp($value,$new.$basename.'/',$recover);
			}
		}
		return true;
	}

	/**
	 * 文件移动操作
	 * @参数 $old 旧文件（夹）
	 * @参数 $new 新文件（夹）
	 * @参数 $recover 是否覆盖
	 * @返回 false/true
	**/
	public function mv($old,$new,$recover=true)
	{
		if(!file_exists($old)){
			return false;
		}
		if(substr($new,-1) == "/"){
			$this->make($new,"dir");
		}else{
			$this->make($new,"file");
		}
		if(file_exists($new)){
			if($recover){
				unlink($new);
			}else{
				return false;
			}
		}else{
			$new = $new.basename($old);
		}
		rename($old,$new);
		return true;
	}

	/**
	 * 获取文件夹列表
	 * @参数 $folder 获取指定文件夹下的列表（仅一层深度）
	 * @返回 数组
	**/
	public function ls($folder)
	{
		$this->read_count++;
		$list = $this->_dir_list($folder);
		if(is_array($list)){
			sort($list,SORT_STRING);
		}
		return $list;
	}

	/**
	 * 获取文件夹及子文件夹等多层文件列表（无限级，长度受系统限制）
	 * @参数 $folder 文件夹
	 * @参数 $list 引用变量
	**/
	public function deep_ls($folder,&$list)
	{
		$this->read_count++;
		$tmplist = $this->_dir_list($folder);
		if($tmplist){
			foreach($tmplist as $key=>$value){
				if(is_dir($value)){
					$this->deep_ls($value,$list);
				}else{
					$list[] = $value;
				}
			}
		}
	}

	/**
	 * 取得文件夹下的列表
	 * @参数 $file 文件（夹）
	 * @参数 $type 仅支持folder或file，为file，直接返回$file本身
	 * @返回 $file或数组
	**/
	private function _dir_list($file,$type="folder")
	{
		if(substr($file,-1) == "/"){
			$file = substr($file,0,-1);
		}
		if(!file_exists($file)){
			return false;
		}
		if($type == "file" || is_file($file)){
			return $file;
		}else{
			$handle = opendir($file);
			$array = array();
			while(false !== ($myfile = readdir($handle))){
				if($myfile != "." && $myfile != ".." && $myfile != ".svn") $array[] = $file."/".$myfile;
			}
			closedir($handle);
			return $array;
		}
	}

	/**
	 * 数组转成字符串
	 * @参数 $array 要转的数组的
	 * @参数 $var 传递的变量
	 * @参数 $content 内容
	 * @返回 
	 * @更新时间 
	**/
	private function __array($array,$var,$content="")
	{
		foreach($array AS $key=>$value){
			if(is_array($value)){
				$content .= $this->__array($value,"".$var."[\"".$key."\"]");
			}else{
				$old_str = array('"',"<?php","?>","\r");
				$new_str = array("'","&lt;?php","?&gt;","");
				$value = str_replace($old_str,$new_str,$value);
				$content .= "\$".$var."[\"".$key."\"] = \"".$value."\";\n";
			}
		}
		return $content;
	}

	/**
	 * 打开文件
	 * @参数 $file 打开的文件
	 * @参数 $type 打开类型，默认是wb
	**/
	private function _open($file,$type="wb")
	{
		$handle = fopen($file,$type);
		$this->read_count++;
		return $handle;
	}

	/**
	 * 写入信息
	 * @参数 $content 内容
	 * @参数 $file 要写入的文件
	 * @参数 $type 打开方式
	 * @返回 true
	**/
	private function _write($content,$file,$type="wb")
	{
		if($content){
			$content = stripslashes($content);
		}
		$handle = $this->_open($file,$type);
		fwrite($handle,$content);
		unset($content);
		$this->_close($handle);
		return true;
	}

	/**
	 * 关闭句柄
	 * @参数 $handle 句柄
	**/
	private function _close($handle)
	{
		return fclose($handle);
	}

	/**
	 * 附件下载
	 * @参数 $file 要下载的文件地址
	 * @参数 $title 下载后的文件名
	**/
	public function download($file,$title='')
	{
		if(!$file){
			return false;
		}
		if(!file_exists($file)){
			return false;
		}
		$ext = pathinfo($file,PATHINFO_EXTENSION);
		$filesize = filesize($file);
		if(!$title){
			$title = basename($file);
		}else{
			$title = str_replace('.'.$ext,'',$title);
			$title.= '.'.$ext;
		}
		ob_end_clean();
		set_time_limit(0);
		header("Content-type: applicatoin/octet-stream");
		header("Date: ".gmdate("D, d M Y H:i:s",time())." GMT");
		header("Last-Modified: ".gmdate("D, d M Y H:i:s",time())." GMT");
		header("Content-Encoding: none");
		header("Content-Disposition: attachment; filename=".rawurlencode($title)."; filename*=utf-8''".rawurlencode($title));
		header("Accept-Ranges: bytes");
		$range = 0;
		$size2 = $filesize -1;
		if (isset ($_SERVER['HTTP_RANGE'])) {
		    list ($a, $range) = explode("=", $_SERVER['HTTP_RANGE']);
		    $new_length = $size2 - $range;
		    header("HTTP/1.1 206 Partial Content");
		    header("Content-Length: ".$new_length); //输入总长
		    header("Content-Range: bytes ".$range."-".$size2."/".$filesize);
		} else {
		    header("Content-Range: bytes 0-".$size2."/".$filesize); //Content-Range: bytes 0-4988927/4988928
		    header("Content-Length: ".$filesize);
		}
		$read_buffer=4096;
		$sum_buffer = 0;
		$handle = fopen($file, "rb");
		fseek($handle, $range);
		ob_start();
		while (!feof($handle) && $sum_buffer<$filesize) {
			echo fread($handle,$read_buffer);
			$sum_buffer+=$read_buffer;
			ob_flush();
			flush();
		}
		ob_end_clean();
		fclose($handle);
	}
}