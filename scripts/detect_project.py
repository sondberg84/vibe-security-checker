#!/usr/bin/env python3
"""
Vibe Security Checker - Project Detection
Identifies project type and recommends security checks
"""

import os
import json
import argparse
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Set

@dataclass
class ProjectInfo:
    project_type: str
    frameworks: List[str]
    languages: List[str]
    databases: List[str]
    cloud_services: List[str]
    ai_tool_indicators: List[str]
    recommended_checks: List[str]

FRAMEWORK_INDICATORS = {
    # Python frameworks
    'django': ['settings.py', 'urls.py', 'wsgi.py', 'asgi.py'],
    'flask': ['app.py', 'flask'],
    'fastapi': ['fastapi', 'uvicorn'],
    'streamlit': ['streamlit'],
    
    # JavaScript frameworks
    'react': ['react', 'jsx', 'tsx', 'create-react-app'],
    'next.js': ['next.config', '_app.js', '_app.tsx', 'pages/', 'app/'],
    'vue': ['vue', '.vue', 'nuxt'],
    'express': ['express', 'app.listen'],
    'nest.js': ['@nestjs'],
    
    # Other
    'rails': ['Gemfile', 'config/routes.rb'],
    'spring': ['pom.xml', 'application.properties'],
}

DATABASE_INDICATORS = {
    'postgresql': ['psycopg', 'pg', 'postgres'],
    'mysql': ['mysql', 'pymysql'],
    'mongodb': ['mongoose', 'pymongo', 'mongodb'],
    'sqlite': ['sqlite3', 'sqlite'],
    'redis': ['redis', 'ioredis'],
    'supabase': ['supabase', '@supabase/supabase-js'],
    'firebase': ['firebase', 'firestore'],
    'prisma': ['prisma'],
}

CLOUD_INDICATORS = {
    'aws': ['boto3', 'aws-sdk', '@aws-sdk'],
    'gcp': ['google-cloud', '@google-cloud'],
    'azure': ['azure', '@azure'],
    'vercel': ['vercel', '@vercel'],
    'netlify': ['netlify'],
    'railway': ['railway'],
    'render': ['render'],
    'supabase': ['supabase'],
    'firebase': ['firebase'],
}

AI_TOOL_INDICATORS = {
    'lovable': ['.lovable', 'lovable.json'],
    'replit': ['.replit', 'replit.nix'],
    'cursor': ['.cursor', '.cursorignore', '.cursorrules'],
    'bolt': ['.bolt'],
    'v0': ['v0.dev'],
    'windsurf': ['.windsurf', '.codeium'],
}

class ProjectDetector:
    def __init__(self, root_path: str):
        self.root = Path(root_path).resolve()
        
    def detect(self) -> ProjectInfo:
        """Detect project characteristics."""
        all_files = self._get_all_files()
        all_content = self._get_content_sample()
        
        project_type = self._detect_project_type(all_files)
        frameworks = self._detect_frameworks(all_files, all_content)
        languages = self._detect_languages(all_files)
        databases = self._detect_databases(all_content)
        cloud_services = self._detect_cloud(all_content)
        ai_indicators = self._detect_ai_tools(all_files)
        
        recommended = self._get_recommendations(
            project_type, frameworks, databases, cloud_services, ai_indicators
        )
        
        return ProjectInfo(
            project_type=project_type,
            frameworks=frameworks,
            languages=languages,
            databases=databases,
            cloud_services=cloud_services,
            ai_tool_indicators=ai_indicators,
            recommended_checks=recommended
        )
    
    def _get_all_files(self) -> Set[str]:
        """Get all file names in project."""
        files = set()
        for root, dirs, filenames in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in {'node_modules', '.git', '__pycache__', '.venv', 'venv'}]
            for f in filenames:
                files.add(f)
                files.add(str(Path(root).relative_to(self.root) / f))
        return files
    
    def _get_content_sample(self) -> str:
        """Get sample of project content for analysis."""
        content_parts = []
        
        # Check key files
        key_files = [
            'package.json', 'requirements.txt', 'pyproject.toml',
            'Gemfile', 'pom.xml', 'go.mod', 'Cargo.toml',
            '.env.example', 'docker-compose.yml'
        ]
        
        for key_file in key_files:
            path = self.root / key_file
            if path.exists():
                try:
                    content_parts.append(path.read_text(errors='ignore')[:5000])
                except:
                    pass
        
        return '\n'.join(content_parts)
    
    def _detect_project_type(self, files: Set[str]) -> str:
        """Detect primary project type."""
        if 'package.json' in files:
            if any('next' in f for f in files):
                return 'next.js'
            if any('.vue' in f for f in files):
                return 'vue'
            return 'node.js'
        if 'requirements.txt' in files or 'pyproject.toml' in files:
            if any('settings.py' in f for f in files):
                return 'django'
            if any('app.py' in f for f in files):
                return 'flask/fastapi'
            return 'python'
        if 'Gemfile' in files:
            return 'ruby/rails'
        if 'pom.xml' in files or 'build.gradle' in files:
            return 'java'
        if 'go.mod' in files:
            return 'go'
        if 'Cargo.toml' in files:
            return 'rust'
        return 'unknown'
    
    def _detect_frameworks(self, files: Set[str], content: str) -> List[str]:
        """Detect frameworks in use."""
        detected = []
        files_lower = {f.lower() for f in files}
        content_lower = content.lower()
        
        for framework, indicators in FRAMEWORK_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in files_lower or indicator.lower() in content_lower:
                    if framework not in detected:
                        detected.append(framework)
                    break
        
        return detected
    
    def _detect_languages(self, files: Set[str]) -> List[str]:
        """Detect programming languages."""
        langs = set()
        ext_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.jsx': 'JavaScript/React',
            '.tsx': 'TypeScript/React',
            '.vue': 'Vue',
            '.rb': 'Ruby',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.php': 'PHP',
        }
        
        for f in files:
            ext = Path(f).suffix.lower()
            if ext in ext_map:
                langs.add(ext_map[ext])
        
        return list(langs)
    
    def _detect_databases(self, content: str) -> List[str]:
        """Detect databases in use."""
        detected = []
        content_lower = content.lower()
        
        for db, indicators in DATABASE_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in content_lower:
                    if db not in detected:
                        detected.append(db)
                    break
        
        return detected
    
    def _detect_cloud(self, content: str) -> List[str]:
        """Detect cloud services."""
        detected = []
        content_lower = content.lower()
        
        for service, indicators in CLOUD_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in content_lower:
                    if service not in detected:
                        detected.append(service)
                    break
        
        return detected
    
    def _detect_ai_tools(self, files: Set[str]) -> List[str]:
        """Detect AI coding tool indicators."""
        detected = []
        
        for tool, indicators in AI_TOOL_INDICATORS.items():
            for indicator in indicators:
                if any(indicator in f for f in files):
                    if tool not in detected:
                        detected.append(tool)
                    break
        
        return detected
    
    def _get_recommendations(self, project_type: str, frameworks: List[str], 
                            databases: List[str], cloud: List[str], 
                            ai_tools: List[str]) -> List[str]:
        """Get recommended security checks based on detection."""
        recommendations = ['secrets']  # Always check secrets
        
        # Database-related checks
        if databases:
            recommendations.append('injection')
        
        # Web framework checks
        web_frameworks = {'flask', 'django', 'fastapi', 'express', 'next.js', 'react', 'vue'}
        if any(f in web_frameworks for f in frameworks):
            recommendations.extend(['xss', 'auth', 'cors'])
        
        # Cloud checks
        if cloud or any(f in {'supabase', 'firebase'} for f in databases):
            recommendations.append('cloud')
        
        # Crypto checks for auth-heavy apps
        if 'django' in frameworks or 'auth' in str(databases).lower():
            recommendations.append('crypto')
        
        # Extra scrutiny for vibe-coded projects
        if ai_tools:
            recommendations.append('data')
            if 'lovable' in ai_tools:
                # Lovable has known RLS issues
                recommendations.insert(0, 'cloud')
        
        return list(dict.fromkeys(recommendations))  # Remove duplicates, preserve order

def main():
    parser = argparse.ArgumentParser(description='Detect project type and recommend security checks')
    parser.add_argument('path', help='Path to project directory')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        return
    
    detector = ProjectDetector(args.path)
    info = detector.detect()
    
    if args.json:
        print(json.dumps({
            'project_type': info.project_type,
            'frameworks': info.frameworks,
            'languages': info.languages,
            'databases': info.databases,
            'cloud_services': info.cloud_services,
            'ai_tool_indicators': info.ai_tool_indicators,
            'recommended_checks': info.recommended_checks
        }, indent=2))
    else:
        print(f"\n{'='*60}")
        print("VIBE SECURITY CHECKER - PROJECT ANALYSIS")
        print(f"{'='*60}\n")
        
        print(f"Project Type: {info.project_type}")
        print(f"Languages: {', '.join(info.languages) or 'Unknown'}")
        print(f"Frameworks: {', '.join(info.frameworks) or 'None detected'}")
        print(f"Databases: {', '.join(info.databases) or 'None detected'}")
        print(f"Cloud Services: {', '.join(info.cloud_services) or 'None detected'}")
        
        if info.ai_tool_indicators:
            print(f"\n⚠️  AI Tool Indicators: {', '.join(info.ai_tool_indicators)}")
            print("   This project appears to be vibe-coded. Extra scrutiny recommended.")
        
        print(f"\n📋 Recommended Security Checks:")
        for check in info.recommended_checks:
            print(f"   • {check}")
        
        print(f"\n💡 Run full scan: python3 scripts/scan_security.py {args.path} --full")

if __name__ == '__main__':
    main()