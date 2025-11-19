def generate_text_report(result_manager, output_file):
    """Generate text report"""
    summary = result_manager.get_summary()
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"NGINX CIS Benchmark Report - {result_manager.host}\n")
        f.write("=" * 50 + "\n\n")
        
        f.write("SUMMARY:\n")
        f.write(f"  Compliance Rate: {summary['pass_rate']:.1f}%\n")
        f.write(f"  Total Checks: {summary['total']}\n")
        f.write(f"  Passed: {summary['pass']}\n")
        f.write(f"  Failed: {summary['fail']}\n")
        f.write(f"  Errors: {summary['error']}\n")
        f.write(f"  Skipped: {summary['skipped']}\n")
        f.write(f"  Duration: {summary['duration']:.2f} seconds\n\n")
        
        f.write("DETAILED RESULTS:\n")
        f.write("-" * 50 + "\n")
        
        for result in result_manager.results:
            status_symbol = {
                'PASS': '✅',
                'FAIL': '❌', 
                'ERROR': '⚠️',
                'SKIPPED': '⏭️'
            }.get(result.status, '❓')
            
            f.write(f"{status_symbol} {result.check_id}: {result.description}\n")
            f.write(f"   Status: {result.status} | Level: {result.level} | Module: {result.module}\n")
            f.write(f"   Message: {result.message}\n\n")